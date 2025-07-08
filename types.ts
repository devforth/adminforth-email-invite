import type { EmailAdapter } from "adminforth";

export interface PluginOptions {
  /**
   * Field name in auth resource which contains email
   */
  emailField: string;

  /**
   * From which email to send invite emails
   * e.g. no-reply@example.com
   */
  sendFrom: string;

  /**
   * Email adapter to use for sending emails
   */
  adapter: EmailAdapter;

  /**
   * Field name in auth resource which stores email confirmation status
   * If provided, email will be marked as confirmed when user sets password via invite
   * e.g. 'email_confirmed'
   */
  emailConfirmedField?: string;
}
