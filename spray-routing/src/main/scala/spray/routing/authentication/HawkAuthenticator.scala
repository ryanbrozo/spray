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
  
case class HawkUser(id: String, key: String, algorithm: String)

class HawkAuthenticator[U](val hawkAuthenticator: HawkCredentialsRetriever[U])(implicit val executionContext: ExecutionContext)
    extends ContextAuthenticator[U] {
  
  def scheme = "Hawk"
  def realm = ""
  def params(ctx: RequestContext): Map[String, String] = Map.empty
  
  def apply(ctx: RequestContext) = {
    val authHeader = ctx.request.headers.findByType[`Authorization`]
    val hostHeader = ctx.request.headers.findByType[`Host`]
    val method = ctx.request.method
    val uri = ctx.request.uri
    val credentials = authHeader.map { case Authorization(creds) ⇒ creds }
    authenticate(credentials, ctx) map {
      case Some(hawkUser) ⇒ Right(hawkUser._2)
      case None ⇒ Left {
        if (authHeader.isEmpty) AuthenticationRequiredRejection(scheme, realm, params(ctx))
        else AuthenticationFailedRejection(realm)
      }
    }
  }
  
  def authenticate(credentials: Option[HttpCredentials], ctx: RequestContext) = {
    hawkAuthenticator {
      credentials.flatMap {
        case GenericHttpCredentials(scheme, token, params) ⇒
          params get "id" match {
            case Some(id) ⇒ Some(id)
            case None     ⇒ None
          }
        case _ ⇒ None
      }
    }
  }
}
