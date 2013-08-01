/*
 * Copyright (C) 2011-2013 spray.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package spray.routing
package authentication

import scala.concurrent.{ ExecutionContext, Future }
import spray.http._
import spray.util._
import HttpHeaders._
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.NoSuchAlgorithmException
import org.parboiled.common.Base64
import spray.http.Uri.Query
import spray.http.HttpMethod
import spray.http.Uri
import spray.routing.AuthenticationFailedRejection._

package object hawk {
  type HawkCredentialsRetriever = Option[String] ⇒ Option[HawkCredentials]
  type UserRetriever[T] = Option[String] ⇒ Future[Option[T]]
  type CurrenTimeProvider = () ⇒ Long
}

package hawk {

  case class HawkCredentials(id: String, key: String, algorithm: String)

  /**
   * A HawkAuthenticator is a ContextAuthenticator that uses credentials passed to the server via the
   * HTTP `Authorization` header to authenticate the user and extract a user object.
   */
  case class HawkAuthenticator[U](val hawkCredsRetriever: HawkCredentialsRetriever,
                                  val userRetriever: UserRetriever[U],
                                  val timeProvider: CurrenTimeProvider)(implicit val executionContext: ExecutionContext)
      extends HttpAuthenticator[U] {

    def scheme = "Hawk"
    def realm = ""
    def params(ctx: RequestContext): Map[String, String] = Map.empty

    override def apply(ctx: RequestContext) = {
      val authHeader = ctx.request.headers.findByType[`Authorization`]
      val credentials = authHeader.map {
        case Authorization(creds) ⇒ creds
      } flatMap {
        case genericCreds: GenericHttpCredentials ⇒ Some(genericCreds)
        case _                                    ⇒ None
      }

      authenticate(credentials, ctx) map {
        case Some(userContext) ⇒ Right(userContext)
        case None ⇒
          val cause = if (authHeader.isEmpty) CredentialsMissing else CredentialsRejected
          Left(AuthenticationFailedRejection(cause, this))
      }
    }

    def authenticate(credentials: Option[HttpCredentials], ctx: RequestContext) = {
      var hawkHttpCredentials: Option[GenericHttpCredentials] = None
      userRetriever {
        //        (credentials map { _.params } map { _ get "id" }).flatten
        hawkCredsRetriever {
          credentials.flatMap {
            case creds: GenericHttpCredentials ⇒ hawkHttpCredentials = Some(creds); creds.params.get("id")
            case _                             ⇒ None
          }
        } match {
          case Some(hawkUser) ⇒
            val method = ctx.request.method
            val uri = ctx.request.uri
            val xForwardedProtoHeader = ctx.request.headers.find {
              header ⇒
                header match {
                  case h: RawHeader if (h.lowercaseName == "x-forwarded-proto") ⇒ true
                  case _ ⇒ false
                }
            }
            val mesg = produceHawkHeader(method, uri, hawkHttpCredentials, xForwardedProtoHeader)
            val hash = calculateMac(hawkUser.key, mesg.toString, hawkUser.algorithm)
            if ((hawkHttpCredentials map { _.params } map { _ get "mac" }).flatten.getOrElse("") == hash) {
              Some(hawkUser.id)
            } else {
              None
            }
          case _ ⇒ None
        }
      }
    }

    def getChallengeHeaders(httpRequest: HttpRequest) =
      `WWW-Authenticate`(HttpChallenge(scheme, realm, params = Map.empty)) :: Nil

    private def produceHawkHeader(method: HttpMethod, uri: Uri, credentials: Option[GenericHttpCredentials],
                                  xForwardedProtoHeader: Option[HttpHeader]) = {
      val params = credentials map { _.params }
      val buf = new StringBuilder
      buf ++= "hawk.1.header\n"
      buf ++= (params map { _ get "ts" }).flatten.getOrElse("") + "\n"
      buf ++= (params map { _ get "nonce" }).flatten.getOrElse("") + "\n"
      buf ++= method.toString + "\n"
      buf ++= uri.path.toString
      buf ++= (uri.query match {
        case Query.Empty ⇒ "\n"
        case x: Query    ⇒ "?" + x.toString + "\n"
      })
      buf ++= uri.authority.host.toString.toLowerCase + "\n"
      buf ++= (uri.authority.port match {
        case i if (i > 0) ⇒ i
        case 0 ⇒
          // Need to determine which scheme to use. Check if we have X-Forwarded-Proto
          // header set (usually by reverse proxies). Use this instead of original
          // scheme when present
          val scheme = xForwardedProtoHeader match {
            case Some(header) ⇒ header.value
            case None         ⇒ uri.scheme
          }
          scheme match {
            case "http"  ⇒ 80
            case "https" ⇒ 443
            case _       ⇒ 0
          }
      }).toString + "\n"

      buf ++= (params map { _ get "hash" }).flatten.getOrElse("") + "\n"
      buf ++= (params map { _ get "ext" }).flatten.getOrElse("") + "\n"
      buf ++= ((params map { _ get "app" }).flatten map {
        case app ⇒ app + "\n" + (params map { _ get "dlg" }).flatten.getOrElse("") + "\n"
      }).getOrElse("")
      buf.toString
    }

    private def calculateMac(key: String, buf: String, algo: String) = {
      val mac = Mac.getInstance(algo)
      mac.init(new SecretKeySpec(key.getBytes("UTF-8"), algo))
      Base64.rfc2045.encodeToString(mac.doFinal(buf.getBytes("UTF-8")), false)
    }
  }
}