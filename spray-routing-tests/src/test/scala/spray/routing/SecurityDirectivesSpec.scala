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

import scala.concurrent.Future
import akka.event.NoLogging
import spray.routing.authentication._
import hawk._
import spray.http._
import HttpHeaders._
import spray.http.Uri.Query
import AuthenticationFailedRejection._

class SecurityDirectivesSpec extends RoutingSpec {

  val dontAuth = BasicAuth(UserPassAuthenticator[BasicUserContext](_ ⇒ Future.successful(None)), "Realm")

  val doAuth = BasicAuth(UserPassAuthenticator[BasicUserContext] { userPassOption ⇒
    Future.successful(Some(BasicUserContext(userPassOption.get.user)))
  }, "Realm")

  "the 'authenticate(BasicAuth())' directive" should {
    "reject requests without Authorization header with an AuthenticationFailedRejection" in {
      Get() ~> {
        authenticate(dontAuth) { echoComplete }
      } ~> check { rejection === AuthenticationFailedRejection(CredentialsMissing, dontAuth) }
    }
    "reject unauthenticated requests with Authorization header with an AuthenticationFailedRejection" in {
      Get() ~> Authorization(BasicHttpCredentials("Bob", "")) ~> {
        authenticate(dontAuth) { echoComplete }
      } ~> check { rejection === AuthenticationFailedRejection(CredentialsRejected, dontAuth) }
    }
    "reject requests with illegal Authorization header with 401" in {
      Get() ~> RawHeader("Authorization", "bob alice") ~> handleRejections(RejectionHandler.Default) {
        authenticate(dontAuth) { echoComplete }
      } ~> check {
        status === StatusCodes.Unauthorized and
          entityAs[String] === "The resource requires authentication, which was not supplied with the request"
      }
    }
    "extract the object representing the user identity created by successful authentication" in {
      Get() ~> Authorization(BasicHttpCredentials("Alice", "")) ~> {
        authenticate(doAuth) { echoComplete }
      } ~> check { entityAs[String] === "BasicUserContext(Alice)" }
    }
    "properly handle exceptions thrown in its inner route" in {
      object TestException extends spray.util.SingletonException
      Get() ~> Authorization(BasicHttpCredentials("Alice", "")) ~> {
        handleExceptions(ExceptionHandler.default) {
          authenticate(doAuth) { _ ⇒ throw TestException }
        }
      } ~> check { status === StatusCodes.InternalServerError }
    }
  }

  "the 'authenticate(<ContextAuthenticator>)' directive" should {
    case object AuthenticationRejection extends Rejection

    val myAuthenticator: ContextAuthenticator[Int] = ctx ⇒ Future {
      Either.cond(ctx.request.uri.authority.host == Uri.NamedHost("spray.io"), 42, AuthenticationRejection)
    }
    "reject requests not satisfying the filter condition" in {
      Get() ~> authenticate(myAuthenticator) { echoComplete } ~>
        check { rejection === AuthenticationRejection }
    }
    "pass on the authenticator extraction if the filter conditions is met" in {
      Get() ~> Host("spray.io") ~> authenticate(myAuthenticator) { echoComplete } ~>
        check { entityAs[String] === "42" }
    }
  }

  val hawkCreds = HawkCredentials("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", "HMACSHA256")

  val hawkDontAuth = HawkAuthenticator[String]({ _ ⇒ Some(hawkCreds) }, { _ ⇒ Future.successful(None) }, { () ⇒ 12345L })

  val hawkDoAuth = HawkAuthenticator[String]({ _ ⇒ Some(hawkCreds) }, { userOption ⇒ Future.successful(userOption.map { _ ⇒ "Bob" }) }, { () ⇒ 12345L })

  val hawkCredentials = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je", "ts" -> "1353832234", "nonce" -> "j4h3g2", "ext" -> "some-app-ext-data", "mac" -> "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="))

  "the 'authenticate(HawkAuthenticator)' directive" should {
    "reject requests without Authorization header with an AuthenticationRequiredRejection" in {
      Get() ~> {
        authenticate(hawkDontAuth) { echoComplete }
      } ~> check { rejection === AuthenticationFailedRejection(CredentialsMissing, hawkDontAuth) }
    }
    "reject unauthenticated requests with Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials) ~>
        {
          authenticate(hawkDontAuth) { echoComplete }
        } ~> check { rejection === AuthenticationFailedRejection(CredentialsRejected, hawkDontAuth) }
    }
    "reject incorrect mac in Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials) ~>
        {
          authenticate(hawkDoAuth) { echoComplete }
        } ~> check { rejection === AuthenticationFailedRejection(CredentialsRejected, hawkDoAuth) }
    }
    "extract the object representing the user identity created by successful authentication" in {
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials) ~>
        {
          authenticate(hawkDoAuth) { echoComplete }
        } ~> check { entityAs[String] === "Bob" }
    }
    "properly handle exceptions thrown in its inner route" in {
      object TestException extends spray.util.SingletonException
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials) ~>
        {
          handleExceptions(ExceptionHandler.default) {
            authenticate(hawkDoAuth) { _ ⇒ throw TestException }
          }
        } ~> check { status === StatusCodes.InternalServerError }
    }
  }
}