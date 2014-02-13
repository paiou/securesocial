/**
 * Copyright 2012-2014 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package securesocial.controllers.registration

import play.api.mvc.{ Result, Action, Controller }
import play.api.mvc.Results._
import play.api.data._
import play.api.data.Forms._
import play.api.data.validation.Constraints._
import play.api.{ Play, Logger }
import securesocial.core.providers.UsernamePasswordProvider
import securesocial.core._
import com.typesafe.plugin._
import Play.current
import securesocial.core.providers.utils._
import org.joda.time.DateTime
import play.api.i18n.Messages
import securesocial.core.providers.Token
import scala.Some
import securesocial.core.IdentityId
import securesocial.controllers.TemplatesPlugin
import securesocial.controllers.ProviderController
import securesocial.controllers.ProviderController.landingUrl
import scala.language.reflectiveCalls

/**
 * Controller to handle one-step user registration.
 *
 */
object FullRegistration extends Controller with securesocial.core.SecureSocial {
  import DefaultRegistration.{
    RegistrationInfo,
    UserName,
    UserNameAlreadyTaken,
    providerId,
    FirstName,
    LastName,
    Password,
    Password1,
    Password2,
    PasswordsDoNotMatch,
    Email,
    Success,
    SignUpDone,
    onHandleStartSignUpGoTo,
    onHandleSignUpGoTo,
    onHandleSignUpGoToOpt,
    ThankYouCheckEmail,
    TokenDurationKey,
    DefaultDuration,
    TokenDuration,
    registrationEnabled,
    createToken,
    executeForToken
  }
  
  val EmailAlreadyTaken = "securesocial.signup.emailAlreadyTaken"

  case class FullRegistrationInfo(userName: Option[String], firstName: String, lastName: String, email: String, password: String)

  val formWithUsername = Form[FullRegistrationInfo](
    mapping(
      UserName -> nonEmptyText.verifying(Messages(UserNameAlreadyTaken), userName => {
        UserService.find(IdentityId(userName, providerId)).isEmpty
      }),
      FirstName -> nonEmptyText,
      LastName -> nonEmptyText,
      Email -> email.verifying(nonEmpty),
      Password ->
        tuple(
          Password1 -> nonEmptyText.verifying(PasswordValidator.constraint),
          Password2 -> nonEmptyText
        ).verifying(Messages(PasswordsDoNotMatch), passwords => passwords._1 == passwords._2)
    )
    // binding
    ((userName, firstName, lastName, email, password) => FullRegistrationInfo(Some(userName), firstName, lastName, email, password._1))
    // unbinding
    (info => Some(info.userName.getOrElse(""), info.firstName, info.lastName, info.email, ("", "")))
  )

  val formWithoutUsername = Form[FullRegistrationInfo](
    mapping(
      FirstName -> nonEmptyText,
      LastName -> nonEmptyText,
      Email -> email.verifying(nonEmpty),
      Password ->
        tuple(
          Password1 -> nonEmptyText.verifying( PasswordValidator.constraint ),
          Password2 -> nonEmptyText
        ).verifying(Messages(PasswordsDoNotMatch), passwords => passwords._1 == passwords._2)
    )
    // binding
    ((firstName, lastName, email, password) => FullRegistrationInfo(None, firstName, lastName, email, password._1))
    // unbinding
    (info => Some(info.firstName, info.lastName, info.email, ("", "")))
  )

  val form = if (UsernamePasswordProvider.withUserNameSupport) formWithUsername else formWithoutUsername

  def signUp = Action { implicit request =>
    if (registrationEnabled) {
      if (Logger.isDebugEnabled) {
        Logger.debug("[securesocial] trying sign up")
      }
      Ok(use[TemplatesPlugin].getFullSignUpPage(form))
    }
    else NotFound(views.html.defaultpages.notFound.render(request, None))
  }

  /**
   * Handles posts from the sign up page
   */

  def handleSignUp = Action { implicit request =>
    if (registrationEnabled) {
      form.bindFromRequest.fold(
        errors => {
          if (Logger.isDebugEnabled) {
            Logger.debug("[securesocial] errors " + errors)
          }
          BadRequest(use[TemplatesPlugin].getFullSignUpPage(errors))
        },
        info => {
          UserService.findByEmailAndProvider(info.email, providerId) match {
            case None =>
              val id = info.email
              val user = SocialUser(
                IdentityId(id, providerId),
                info.firstName,
                info.lastName,
                "%s %s".format(info.firstName, info.lastName),
                State.NotValidated,
                Some(info.email),
                GravatarHelper.avatarFor(info.email),
                AuthenticationMethod.UserPassword,
                passwordInfo = Some(Registry.hashers.currentHasher.hash(info.password)))
              UserService.save(user)
              Events.fire(new SignUpEvent(user)).getOrElse(session)
              val token = createToken(info.email, isSignUp = true)
              Mailer.sendVerificationEmail(info.email, token._1)
            case Some(alreadyRegisteredUser) =>
              Mailer.sendAlreadyRegisteredEmail(alreadyRegisteredUser)
          }
          Redirect(onHandleStartSignUpGoTo).flashing(Success -> Messages(ThankYouCheckEmail), Email -> info.email)
        }
      )
    }
    else NotFound(views.html.defaultpages.notFound.render(request, None))
  }

  def signUpVerification(token: String) = UserAwareAction { implicit request =>
    if (registrationEnabled) {
 
      def markAsActive(user: Identity) = {
        val updated = UserService.save(SocialUser(user).copy(state = State.ValidEmail))
        Mailer.sendWelcomeEmail(updated)
        val eventSession = Events.fire(new SignUpEvent(updated)).getOrElse(session)
        if ( UsernamePasswordProvider.signupSkipLogin ) {
          val authResult = ProviderController.completeAuthentication(updated, eventSession).flashing(Success -> Messages(SignUpDone))
          onHandleSignUpGoToOpt.map { targetUrl =>
            authResult.withHeaders(LOCATION -> targetUrl)
          } getOrElse authResult
        } else {
          Redirect(onHandleSignUpGoTo).flashing(Success -> Messages(SignUpDone)).withSession(eventSession)
        }
      }

      executeForToken(token, true, { t =>
        val email = t.email
        val providerId = t.uuid
        val userFromToken = UserService.findByEmailAndProvider(email, UsernamePasswordProvider.UsernamePassword)
        (userFromToken, request.user) match {
          case (Some(user), Some(user2)) if user.identityId == user2.identityId =>
            markAsActive(user)
          case (Some(user), None) =>
            markAsActive(user)
          case _ =>
            Unauthorized("Not Authorized Page")
        }
      })
    }
    else NotFound(views.html.defaultpages.notFound.render(request, None))
  }
}
