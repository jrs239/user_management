# app/services/email_service.py
from builtins import ValueError, dict, str
from typing import Optional
from settings.config import settings
from app.utils.smtp_connection import SMTPClient
from app.utils.template_manager import TemplateManager
from app.models.user_model import User

class EmailService:
    def __init__(self, template_manager: TemplateManager):
        self.smtp_client = SMTPClient(
            server=settings.smtp_server,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password
        )
        self.template_manager = template_manager

    async def send_user_email(self, user_data: dict, email_type: str):
        subject_map = {
            'email_verification': "Verify Your Account",
            'password_reset': "Password Reset Instructions",
            'account_locked': "Account Locked Notification"
        }

        if email_type not in subject_map:
            raise ValueError("Invalid email type")

        html_content = self.template_manager.render_template(email_type, **user_data)
        # use smtp_client directly (there is no self.send_email here)
        self.smtp_client.send_email(subject_map[email_type], html_content, user_data['email'])

    async def send_verification_email(self, user: User):
        verification_url = f"{settings.server_base_url}verify-email/{user.id}/{user.verification_token}"
        await self.send_user_email({
            "name": user.first_name,
            "verification_url": verification_url,
            "email": user.email
        }, 'email_verification')

    async def send_pro_upgrade_notice(self, user: User, cc: Optional[list[str]] = None) -> None:
        """
        Notify the user they were upgraded to Professional.
        """
        subject = "You're now a Professional user 🎉"
        # Keep it simple text; your SMTPClient already handles sending
        body = (
            f"Hi {user.first_name or 'there'},\n\n"
            "Good news — your account has been upgraded to Professional.\n"
            "You now have access to pro features immediately.\n\n"
            "If you have any questions, just reply to this email.\n\n"
            "— The Team"
        )
        # send via SMTPClient (no self.send_email method exists in this class)
        self.smtp_client.send_email(subject, body, user.email, cc=cc)
