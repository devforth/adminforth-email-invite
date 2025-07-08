import AdminForth, { AdminForthPlugin, suggestIfTypo, Filters } from "adminforth";
import type { IAdminForth, IHttpServer, AdminForthResourcePages, AdminForthResourceColumn, AdminForthDataTypes, AdminForthResource, AdminUser, HttpExtra } from "adminforth";
import type { PluginOptions } from './types.js';

export default class EmailInvitePlugin extends AdminForthPlugin {
  options: PluginOptions;
  authResource!: AdminForthResource;
  emailField!: AdminForthResourceColumn;
  emailConfirmedField?: AdminForthResourceColumn;

  constructor(options: PluginOptions) {
    super(options, import.meta.url);
    this.options = options;
  }

  async modifyResourceConfig(adminforth: IAdminForth, resourceConfig: AdminForthResource) {
    super.modifyResourceConfig(adminforth, resourceConfig);
  
    if (!this.options.emailField) {
      throw new Error(`emailField is required and should be a name of field in auth resource`);
    }

    if (!this.options.sendFrom) {
      throw new Error(`sendFrom is required and should be a valid email address`);
    }

    if (!this.options.adapter) {
      throw new Error('Adapter is required. Please provide a valid email adapter in the plugin options.');
    }

    if (!adminforth.config.auth) {
      throw new Error('Auth configuration is required for email invite plugin');
    }

    // find field with name resourceConfig.emailField in adminforth.auth.usersResourceId and show error if it doesn't exist
    const authResource = adminforth.config.resources.find(r => r.resourceId === adminforth.config.auth!.usersResourceId);
    if (!authResource) {
      throw new Error(`Resource with id config.auth.usersResourceId=${adminforth.config.auth!.usersResourceId} not found`);
    }
    this.authResource = authResource;

    const emailField = authResource.columns.find(f => f.name === this.options.emailField);
    if (!emailField) {
      const similar = suggestIfTypo(authResource.columns.map(f => f.name), this.options.emailField);

      throw new Error(`Field with name ${this.options.emailField} not found in resource ${authResource.resourceId}.
        ${similar ? `Did you mean ${similar}?` : ''}
      `);
    }
    this.emailField = emailField;

    // Check for email confirmation field if specified
    if (this.options.emailConfirmedField) {
      const emailConfirmedField = authResource.columns.find(f => f.name === this.options.emailConfirmedField);
      if (!emailConfirmedField) {
        const similar = suggestIfTypo(authResource.columns.map(f => f.name), this.options.emailConfirmedField);

        throw new Error(`Email confirmed field with name ${this.options.emailConfirmedField} not found in resource ${authResource.resourceId}.
          ${similar ? `Did you mean ${similar}?` : ''}
        `);
      }
      this.emailConfirmedField = emailConfirmedField;
    }

    // Add hooks to handle user creation and invitation email
    if (!authResource.hooks) {
      authResource.hooks = {};
    }
    if (!authResource.hooks.create) {
      authResource.hooks.create = {};
    }
    
    // Add beforeSave hook to handle password field
    if (!authResource.hooks.create.beforeSave) {
      authResource.hooks.create.beforeSave = [];
    }
    if (!Array.isArray(authResource.hooks.create.beforeSave)) {
      authResource.hooks.create.beforeSave = [authResource.hooks.create.beforeSave];
    }
    authResource.hooks.create.beforeSave.push(this.handleUserCreation.bind(this));

    // Add afterSave hook to send invitation email
    if (!authResource.hooks.create.afterSave) {
      authResource.hooks.create.afterSave = [];
    }
    if (!Array.isArray(authResource.hooks.create.afterSave)) {
      authResource.hooks.create.afterSave = [authResource.hooks.create.afterSave];
    }
    authResource.hooks.create.afterSave.push(this.sendInviteEmail.bind(this));

    // Add custom page for setting password
    adminforth.config.customization.customPages.push({
      path: '/set-password',
      component: { 
        file: this.componentPath('SetPassword.vue'), 
        meta: { 
          customLayout: true, 
          pluginInstanceId: this.pluginInstanceId
        }
      }
    });
  }
  
  validateConfigAfterDiscover(adminforth: IAdminForth, resourceConfig: AdminForthResource) {
    // Validate the email adapter
    this.options.adapter.validate();
  }

  instanceUniqueRepresentation(pluginOptions: any): string {
    return `single`;
  }

  async handleUserCreation({ resource, adminUser, record, adminforth, extra }: {
    resource: AdminForthResource;
    adminUser: AdminUser;
    record: any;
    adminforth: IAdminForth;
    extra?: HttpExtra;
  }): Promise<{ok: boolean, error?: string}> {
    try {
      // Remove any password field from record since users will set it via invite
      if ('password' in record) {
        delete record.password;
      }

      // Set password_hash to a temporary placeholder (users will set password via email invite)
      const passwordHashFieldName = adminforth.config.auth!.passwordHashField;
      // Generate a placeholder hash that will be replaced when user sets their password
      record[passwordHashFieldName] = await AdminForth.Utils.generatePasswordHash('TEMP_INVITE_PLACEHOLDER_' + Date.now());

      // Set email as unconfirmed if email confirmation is enabled
      if (this.options.emailConfirmedField && this.emailConfirmedField) {
        record[this.emailConfirmedField.name] = false;
      }

      return { ok: true };
    } catch (error) {
      console.error('Error in handleUserCreation:', error);
      return { ok: false, error: 'Failed to prepare user for creation' };
    }
  }

  async sendInviteEmail({ recordId, resource, record, adminUser, adminforth, extra }: {
    recordId: any;
    resource: AdminForthResource;
    record: any;
    adminUser: AdminUser;
    adminforth: IAdminForth;
    extra?: HttpExtra;
  }): Promise<{ok: boolean, error?: string}> {
    try {
      const email = record[this.options.emailField];
      
      if (!email || !/\S+@\S+\.\S+/.test(email)) {
        console.warn('Email invite plugin: Invalid or missing email address');
        return { ok: true }; // Don't fail user creation for email issues
      }

      const brandName = adminforth.config.customization.brandName || 'Admin Panel';
      
             // Generate invite token
       const inviteToken = adminforth.auth.issueJWT(
         { email, recordId, inviteEmail: true }, 
         'inviteUser', 
         '7d' // 7 days validity
       );

       console.log('Sending invite email to:', email);
       console.log('Generated JWT token payload:', { email, recordId, inviteEmail: true });

             // Build invite URL
       const host = extra?.headers?.host || 'localhost';
       const protocol = extra?.headers?.['x-forwarded-proto'] || 'http';
       const inviteUrl = `${protocol}://${host}/set-password?token=${inviteToken}`;

       // Prepare email content
       const emailSubject = `You're invited to ${brandName}`;
       const emailText = `
         Dear user,
         
         You have been invited to join ${brandName}. To complete your registration and set your password, click the link below:
         
         ${inviteUrl}
         
         If you didn't expect this invitation, please ignore this email.
         Link is valid for 7 days.
         
         Thanks,
         The ${brandName} Team
       `;
       
       const emailHtml = `
         <html>
           <head></head>
           <body>
             <p>Dear user,</p>
             <p>You have been invited to join ${brandName}. To complete your registration and set your password, click the link below:</p>
             <p><a href="${inviteUrl}">Set your password</a></p>
             <p>If you didn't expect this invitation, please ignore this email.</p>
             <p>Link is valid for 7 days.</p>
             <p>Thanks,</p>
             <p>The ${brandName} Team</p>
           </body>
         </html>
       `;

             // Send email
       const result = await this.options.adapter.sendEmail(
         this.options.sendFrom,
         email,
         emailText,
         emailHtml,
         emailSubject
       );

       if (result && result.error) {
         console.error('Failed to send invite email:', result.error);
       } else {
         console.log('Invite email sent successfully to:', email);
       }

      return { ok: true };
    } catch (error) {
      console.error('Error sending invite email:', error);
      return { ok: true }; // Don't fail user creation for email issues
    }
  }

  setupEndpoints(server: IHttpServer) {
    server.endpoint({
      method: 'POST',
      path: `/plugin/${this.pluginInstanceId}/set-password`,
      noAuth: true,
      handler: async ({ body }) => {
        const { token, password } = body;
        
        try {
          const decoded = await this.adminforth.auth.verify(token, 'inviteUser', false);
          if (!decoded || !decoded.inviteEmail) {
            return { error: 'Invalid or expired invitation token', ok: false };
          }

          console.log('Decoded JWT token:', decoded);
          const { email, recordId } = decoded;

          // Find the user record - try by recordId first, then by email as fallback
          let userRecord;
          
          if (recordId) {
            userRecord = await this.adminforth.resource(this.authResource.resourceId).get(recordId);
          }
          
          // If not found by recordId or recordId is missing, try finding by email
          if (!userRecord && email) {
            const records = await this.adminforth.resource(this.authResource.resourceId).list(
              Filters.EQ(this.options.emailField, email),
              1
            );
            userRecord = records.length > 0 ? records[0] : null;
          }
          
          if (!userRecord) {
            return { error: 'User not found', ok: false };
          }

          // Verify email matches (case-insensitive comparison)
          const userEmail = userRecord[this.options.emailField];
          const tokenEmail = email;
          
          console.log('Email verification - User record email:', userEmail, 'Token email:', tokenEmail);
          
          if (!userEmail || userEmail.toLowerCase() !== tokenEmail.toLowerCase()) {
            return { error: 'Email mismatch', ok: false };
          }

          // Hash the password
          const passwordHashFieldName = this.adminforth.config.auth.passwordHashField;
          const newPasswordHash = await AdminForth.Utils.generatePasswordHash(password);
          
          // Get the primary key value for the user record
          const primaryKeyField = this.authResource.columns.find(c => c.primaryKey);
          const userRecordId = userRecord[primaryKeyField!.name];
          
          // Prepare update object
          const updateData: any = { 
            [passwordHashFieldName]: newPasswordHash 
          };

          // Mark email as confirmed if email confirmation is enabled
          if (this.options.emailConfirmedField && this.emailConfirmedField) {
            updateData[this.emailConfirmedField.name] = true;
          }
          
          // Update the user with the password hash and email confirmation
          await this.adminforth.resource(this.authResource.resourceId).update(userRecordId, updateData);

          console.log('Password set successfully for user:', email);

          return { ok: true };
        } catch (error) {
          console.error('Error setting password:', error);
          return { error: 'Failed to set password', ok: false };
        }
      }
    });

    server.endpoint({
      method: 'POST',
      path: `/plugin/${this.pluginInstanceId}/resend-invite`,
      handler: async ({ body, adminUser, extra }) => {
        const { recordId } = body;
        
        try {
          // Get the user record
          const userRecord = await this.adminforth.resource(this.authResource.resourceId).get(recordId);
          if (!userRecord) {
            return { error: 'User not found', ok: false };
          }

          // Simulate the afterSave hook call to resend invite
          await this.sendInviteEmail({
            recordId,
            resource: this.authResource,
            record: userRecord,
            adminUser,
            adminforth: this.adminforth,
            extra
          });

          return { ok: true };
        } catch (error) {
          console.error('Error resending invite:', error);
          return { error: 'Failed to resend invitation', ok: false };
        }
      }
    });
  }
}