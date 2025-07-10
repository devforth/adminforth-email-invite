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

    if (!this.options.passwordField) {
      throw new Error(`passwordField is required to get password constraints and should be a name of virtual field in auth resource`);
    }

    const passwordField = authResource.columns.find(f => f.name === this.options.passwordField);
    if (!passwordField) {
      const similar = suggestIfTypo(authResource.columns.map(f => f.name), this.options.passwordField);

      throw new Error(`Field with name ${this.options.passwordField} not found in resource ${authResource.resourceId}.
        ${similar ? `Did you mean ${similar}?` : ''}
      `);
    }

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

    if (!authResource.hooks) {
      authResource.hooks = {};
    }
    if (!authResource.hooks.create) {
      authResource.hooks.create = {};
    }
    
    if (!authResource.hooks.create.beforeSave) {
      authResource.hooks.create.beforeSave = [];
    }
    if (!Array.isArray(authResource.hooks.create.beforeSave)) {
      authResource.hooks.create.beforeSave = [authResource.hooks.create.beforeSave];
    }
    authResource.hooks.create.beforeSave.push(this.handleUserCreation.bind(this));

    if (!authResource.hooks.create.afterSave) {
      authResource.hooks.create.afterSave = [];
    }
    if (!Array.isArray(authResource.hooks.create.afterSave)) {
      authResource.hooks.create.afterSave = [authResource.hooks.create.afterSave];
    }
    authResource.hooks.create.afterSave.push(this.sendInviteEmail.bind(this));

    adminforth.config.customization.customPages.push({
      path: '/set-password',
      component: { 
        file: this.componentPath('SetPassword.vue'), 
        meta: { 
          customLayout: true, 
          pluginInstanceId: this.pluginInstanceId,
          passwordField: {
            minLength: passwordField.minLength,
            maxLength: passwordField.maxLength,
            validation: passwordField.validation
          }
        }
      }
    });
  }
  
  validateConfigAfterDiscover(adminforth: IAdminForth, resourceConfig: AdminForthResource) {
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

      const passwordHashFieldName = adminforth.config.auth!.passwordHashField;
      record[passwordHashFieldName] = await AdminForth.Utils.generatePasswordHash('TEMP_INVITE_PLACEHOLDER_' + Date.now());

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
      
       const inviteToken = adminforth.auth.issueJWT(
         { email, recordId, inviteEmail: true }, 
         'inviteUser', 
         '7d' // 7 days validity
       );

       console.log('Sending invite email to:', email);
       console.log('Generated JWT token payload:', { email, recordId, inviteEmail: true });

       const host = extra?.headers?.host || 'localhost';
       const protocol = extra?.headers?.['x-forwarded-proto'] || 'http';
       const inviteUrl = `${protocol}://${host}/set-password?token=${inviteToken}`;

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
      return { ok: true };
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
          const { email, recordId } = decoded;

          let userRecord;
          
          if (recordId) {
            userRecord = await this.adminforth.resource(this.authResource.resourceId).get(recordId);
          }
          
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

          const userEmail = userRecord[this.options.emailField];
          const tokenEmail = email;
          
          if (!userEmail || userEmail.toLowerCase() !== tokenEmail.toLowerCase()) {
            return { error: 'Email mismatch', ok: false };
          }

          const passwordHashFieldName = this.adminforth.config.auth.passwordHashField;
          const newPasswordHash = await AdminForth.Utils.generatePasswordHash(password);
          
          const primaryKeyField = this.authResource.columns.find(c => c.primaryKey);
          const userRecordId = userRecord[primaryKeyField!.name];
          
          const updateData: any = { 
            [passwordHashFieldName]: newPasswordHash 
          };

          if (this.options.emailConfirmedField && this.emailConfirmedField) {
            updateData[this.emailConfirmedField.name] = true;
          }
          
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