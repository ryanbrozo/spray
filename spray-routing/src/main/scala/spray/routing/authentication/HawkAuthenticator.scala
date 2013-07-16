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

package object hawk {
  type HawkCredentialsRetriever[T] = Option[String] ⇒ Future[Option[(HawkCredentials[T])]]
  type CurrenTimeProvider = () ⇒ Long
}

package hawk {

  case class HawkCredentials[T](id: String, key: String, algorithm: String, user: T)

  /**
   * A HawkAuthenticator is a ContextAuthenticator that uses credentials passed to the server via the
   * HTTP `Authorization` header to authenticate the user and extract a user object.
   */
  case class HawkAuthenticator[U](val hawkAuthenticator: HawkCredentialsRetriever[U], val timeProvider: CurrenTimeProvider)(implicit val executionContext: ExecutionContext)
      extends ContextAuthenticator[U] {

    def scheme = "Hawk"
    def realm = ""
    def params(ctx: RequestContext): Map[String, String] = Map.empty

    def apply(ctx: RequestContext) = {
      val authHeader = ctx.request.headers.findByType[`Authorization`]
      val method = ctx.request.method
      val uri = ctx.request.uri
      val credentials = authHeader.map {
        case Authorization(creds) ⇒ creds
      } flatMap {
        case genericCreds: GenericHttpCredentials ⇒ Some(genericCreds)
        case _                                    ⇒ None
      }

      authenticate(credentials, ctx) map {
        case Some(hawkUser) ⇒
          val mesg = produceHawkHeader(method, uri, credentials)
          val hash = calculateMac(hawkUser.key, mesg.toString, hawkUser.algorithm)
          if ((credentials map { _.params } map { _ get "mac" }).flatten.getOrElse("") == hash) {
            Right(hawkUser.user)
          } else {
            Left(AuthenticationFailedRejection(realm))
          }
        case None ⇒ Left {
          if (authHeader.isEmpty) AuthenticationRequiredRejection(scheme, realm, params(ctx))
          else AuthenticationFailedRejection(realm)
        }
      }
    }

    def authenticate(credentials: Option[GenericHttpCredentials], ctx: RequestContext) = {
      hawkAuthenticator {
        (credentials map { _.params } map { _ get "id" }).flatten
      }
    }

    private def produceHawkHeader(method: HttpMethod, uri: Uri, credentials: Option[GenericHttpCredentials]) = {
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
          uri.scheme match {
            case "http"  ⇒ 80
            case "https" ⇒ 443
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