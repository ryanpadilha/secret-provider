/*
 *
 *  * Copyright 2017-2020 Lenses.io Ltd
 *
 */

package io.lenses.connect.secrets.providers

import com.amazonaws.DefaultRequest
import com.amazonaws.auth.{AWS4Signer, DefaultAWSCredentialsProviderChain}
import com.amazonaws.http.HttpMethodName
import io.github.jopenlibs.vault.SslConfig
import io.github.jopenlibs.vault.Vault
import io.github.jopenlibs.vault.VaultConfig
import io.github.jopenlibs.vault.response.LogicalResponse
import com.typesafe.scalalogging.LazyLogging
import com.typesafe.scalalogging.StrictLogging
import io.lenses.connect.secrets.cache.ValueWithTtl
import io.lenses.connect.secrets.config.VaultAuthMethod
import io.lenses.connect.secrets.config.VaultSettings
import io.lenses.connect.secrets.connect.decodeKey
import io.lenses.connect.secrets.io.FileWriter
import io.lenses.connect.secrets.utils.EncodingAndId
import io.lenses.connect.secrets.utils.ExceptionUtils.failWithEx
import org.apache.kafka.connect.errors.ConnectException
import play.api.libs.json.Json
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.utils.BinaryUtils

import java.io.{ByteArrayInputStream, File}
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Duration
import java.time.temporal.ChronoUnit
import scala.util.Failure
import scala.util.Success
import scala.util.Try
import java.net.URI
import java.util
import scala.jdk.CollectionConverters._

class VaultHelper(
  vaultClient:        Vault,
  defaultTtl:         Option[Duration],
  fileWriterCreateFn: () => Option[FileWriter],
)(
  implicit
  clock: Clock,
) extends SecretHelper
    with LazyLogging {
  override def lookup(path: String): Either[Throwable, ValueWithTtl[Map[String, String]]] = {
    logger.debug(s"Looking up value from Vault at [$path]")
    Try(vaultClient.logical().read(path)) match {
      case Failure(ex) =>
        failWithEx(s"Failed to fetch secrets from path [$path]", ex)
      case Success(response) if response.getRestResponse.getStatus != 200 =>
        failWithEx(
          s"No secrets found at path [$path]. Vault response: ${new String(response.getRestResponse.getBody)}",
        )
      case Success(response) if response.getData.isEmpty =>
        failWithEx(s"No secrets found at path [$path]")
      case Success(response) =>
        val ttl =
          Option(response.getLeaseDuration).filterNot(_ == 0L).map(Duration.of(_, ChronoUnit.SECONDS))
        Right(
          ValueWithTtl(ttl, defaultTtl, parseSuccessfulResponse(response)),
        )
    }
  }

  private def parseSuccessfulResponse(
    response: LogicalResponse,
  ) = {
    val secretValues    = response.getData.asScala
    val fileWriterMaybe = fileWriterCreateFn()
    secretValues.map {
      case (k, v) =>
        (k,
         decodeKey(
           encoding = EncodingAndId.from(k).encoding,
           key      = k,
           value    = v,
           writeFileFn = { content =>
             fileWriterMaybe.fold("nofile")(_.write(k.toLowerCase, content, k).toString)
           },
         ),
        )
    }.toMap
  }
}

object VaultHelper extends StrictLogging {

  // initialize the vault client
  def createClient(settings: VaultSettings): Vault = {
    val config = new VaultConfig().address(settings.addr)

    // set ssl if configured
    config.sslConfig(configureSSL(settings))

    if (settings.namespace.nonEmpty) {
      logger.info(s"Setting namespace to ${settings.namespace}")
      config.nameSpace(settings.namespace)
    }

    logger.info(s"Setting engine version to ${settings.engineVersion}")
    config.engineVersion(settings.engineVersion)

    val vault = new Vault(config.build())

    logger.info(
      s"Initializing client with mode [${settings.authMode.toString}]",
    )

    config.token(getAuthToken(vault, settings).get)
    config.build()
    new Vault(config)
  }

  private def getAuthToken(vault: Vault, settings: VaultSettings): Option[String] = {
    val token = settings.authMode match {
      case VaultAuthMethod.USERPASS =>
        settings.userPass
          .map(up =>
            vault
              .auth()
              .loginByUserPass(up.username, up.password.value(), up.mount)
              .getAuthClientToken,
          )

      case VaultAuthMethod.APPROLE =>
        settings.appRole
          .map(ar =>
            vault
              .auth()
              .loginByAppRole(ar.path, ar.role, ar.secretId.value())
              .getAuthClientToken,
          )

      case VaultAuthMethod.CERT =>
        settings.cert
          .map(c => vault.auth().loginByCert(c.mount).getAuthClientToken)

      case VaultAuthMethod.AWSIAM =>
        settings.awsIam
          .map(aws =>
            vault
              .auth()
              .loginByAwsIam(
                aws.role,
                aws.url,
                aws.body.value(),
                getDynamicHeaders(aws.iamServerId.getOrElse(settings.addr)),
                aws.mount,
              )
              .getAuthClientToken,
          )

      case VaultAuthMethod.KUBERNETES =>
        settings.k8s
          .map(k8s =>
            vault
              .auth()
              .loginByJwt("kubernetes", k8s.role, k8s.jwt.value(), k8s.authPath)
              .getAuthClientToken,
          )
      case VaultAuthMethod.GCP =>
        settings.gcp
          .map(gcp =>
            vault
              .auth()
              .loginByGCP(gcp.role, gcp.jwt.value())
              .getAuthClientToken,
          )

      case VaultAuthMethod.LDAP =>
        settings.ldap
          .map(l =>
            vault
              .auth()
              .loginByLDAP(l.username, l.password.value(), l.mount)
              .getAuthClientToken,
          )

      case VaultAuthMethod.JWT =>
        settings.jwt
          .map(j =>
            vault
              .auth()
              .loginByJwt(j.provider, j.role, j.jwt.value())
              .getAuthClientToken,
          )

      case VaultAuthMethod.TOKEN =>
        Some(settings.token.value())

      case VaultAuthMethod.GITHUB =>
        settings.github
          .map(gh =>
            vault
              .auth()
              .loginByGithub(gh.token.value(), gh.mount)
              .getAuthClientToken,
          )

      case _ =>
        throw new ConnectException(
          s"Unsupported auth method [${settings.authMode.toString}]",
        )
    }

    token
  }

  // request STS for header
  private def getDynamicHeaders(serverId: String): String = {
    logger.info("invoke aws getDynamicHeaders")

    val region = Region.US_EAST_1.toString
    val credentialsProvider = new DefaultAWSCredentialsProviderChain().getCredentials
    val endpoint = "https://sts.amazonaws.com"
    val body = "Action=GetCallerIdentity&Version=2011-06-15"
    val serviceName = "sts"

    val headers = new util.HashMap[String, String]()
    headers.put("X-Vault-AWS-IAM-Server-ID", serverId)
    headers.put("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

    val defaultRequest = new DefaultRequest(serviceName)
    defaultRequest.setContent(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)))
    defaultRequest.setHeaders(headers)
    defaultRequest.setHttpMethod(HttpMethodName.POST)
    defaultRequest.setEndpoint(new URI(endpoint))

    val signer = new AWS4Signer()
    signer.setServiceName(defaultRequest.getServiceName)
    signer.setRegionName(region)
    signer.sign(defaultRequest, credentialsProvider)

    val signedHeaders = new util.HashMap[String, String]()
    defaultRequest.getHeaders.asScala.map(entry => signedHeaders.put(entry._1, entry._2))

    val payload = Json.toJson(signedHeaders.asScala).toString()
    val base64Headers = BinaryUtils.toBase64(payload.getBytes(StandardCharsets.UTF_8))
    logger.info("base64header aws getDynamicHeaders :: %s".format(base64Headers))

    base64Headers
  }

  // set up tls
  private def configureSSL(settings: VaultSettings): SslConfig = {
    val ssl = new SslConfig()

    if (settings.keystoreLoc != "") {
      logger.info(s"Configuring keystore at [${settings.keystoreLoc}]")
      ssl.keyStoreFile(
        new File(settings.keystoreLoc),
        settings.keystorePass.value(),
      )
    }

    if (settings.truststoreLoc != "") {
      logger.info(s"Configuring keystore at [${settings.truststoreLoc}]")
      ssl.trustStoreFile(new File(settings.truststoreLoc))
    }

    if (settings.clientPem != "") {
      logger.info(s"Configuring client PEM. Ignored if JKS set.")
      ssl.clientKeyPemFile(new File(settings.clientPem))
    }

    if (settings.pem != "") {
      logger.info(s"Configuring Vault Server PEM. Ignored if JKS set.")
      ssl.pemFile(new File(settings.pem))
    }

    ssl.build()
  }
}
