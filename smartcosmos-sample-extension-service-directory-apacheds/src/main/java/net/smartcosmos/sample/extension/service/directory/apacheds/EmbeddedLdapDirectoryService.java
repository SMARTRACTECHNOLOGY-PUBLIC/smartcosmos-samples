package net.smartcosmos.sample.extension.service.directory.apacheds;

/*
 * *#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
 * SMART COSMOS Service Extension - Directory - ApacheDS
 * ===============================================================================
 * Copyright (C) 2015 SMARTRAC Technology Fletcher, Inc.
 * ===============================================================================
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#
 */

import freemarker.template.Configuration;
import freemarker.template.Template;
import io.dropwizard.auth.basic.BasicCredentials;
import net.smartcosmos.model.context.IUser;
import net.smartcosmos.model.context.RoleType;
import net.smartcosmos.platform.api.authentication.IAuthenticatedUser;
import net.smartcosmos.platform.api.authentication.ICredentials;
import net.smartcosmos.platform.api.authentication.IRegistration;
import net.smartcosmos.platform.api.service.IDirectoryService;
import net.smartcosmos.platform.api.service.IEmailService;
import net.smartcosmos.platform.api.service.ITemplateService;
import net.smartcosmos.platform.base.AbstractService;
import net.smartcosmos.platform.pojo.authentication.AuthenticatedUser;
import net.smartcosmos.sample.extensions.server.apacheds.ApacheDSServerExtension;
import net.smartcosmos.sample.extensions.server.apacheds.DirectoryConfiguration;
import net.smartcosmos.util.CryptoUtil;
import net.smartcosmos.util.HashUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

public class EmbeddedLdapDirectoryService extends AbstractService implements IDirectoryService
{

    private static final Logger LOG = LoggerFactory.getLogger(EmbeddedLdapDirectoryService.class);

    public static final String GROUP_ADMINS = "Administrators";

    public static final String GROUP_USERS = "Users";

    public static final String POSTAL_CODE_ENABLED_HACK = "postalCode";

    public static final String DOCUMENT_IDENTIFIER_PASSWORD_RESET = "Password Reset";

    private DirectoryConfiguration directoryFactory;

    private DirContext rootDirContext;

    public EmbeddedLdapDirectoryService()
    {
        super("cfdb4f3e-38bc-4677-925b-1893703c80b5", "Embedded LDAP Directory Service");
    }

    @Override
    public void createDirectory(IRegistration registration)
    {
        createOrgUnit(registration);
        createGroup(GROUP_ADMINS, registration);
        createGroup(GROUP_USERS, registration);
    }

    @Override
    public RoleType lookupUserRole(IUser user)
    {
        RoleType roleType = RoleType.User;

        String realm = context.getDAOFactory().getRegistrationDAO().lookupRealm(user.getAccount());

        String adminsGroupDN = String.format("cn=%s,ou=%s,dc=%s,dc=%s",
                GROUP_ADMINS,
                realm,
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            if (isUserInRole(user, adminsGroupDN))
            {
                roleType = RoleType.Administrator;
            }

        } catch (NamingException e)
        {
            LOG.error("Unable to locate LDAP sub-context: {}", new Object[]{adminsGroupDN});
            LOG.error(e.getMessage());
        }

        return roleType;
    }


    @Override
    public String createUser(IUser user, RoleType roleType)
    {
        String realm = context.getDAOFactory().getRegistrationDAO().lookupRealm(user.getAccount());

        String commonName = ((user.getGivenName() == null) ? "" : user.getGivenName()) +
                ((user.getSurname() == null) ? "" : user.getSurname());

        Attribute cn = new BasicAttribute("cn", commonName);
        Attribute sn = new BasicAttribute("sn", (user.getSurname() == null) ? "" : user.getSurname());

        //
        // Yes, this is a hack.
        // Yes, it's an ugly hack.
        // Yes, it is quick, dirty, and ApacheDS is being treated as a BLACK BOX in SMART COSMOS in this sample
        //
        // Postal Code field is being used to indicated if user is enabled / disabled
        // since ApacheDS doesn't come pre-loaded with a schema that met our needs.
        Attribute postalCode = new BasicAttribute(POSTAL_CODE_ENABLED_HACK, "true");

        Attribute mail = new BasicAttribute("mail", user.getEmailAddress());

        final String randomPassword = HashUtil.createRandomPassword();
        final String hashedEncodedCredentials = CryptoUtil.digestThenEncodePasswordForLDAP("SHA", randomPassword);

        Attribute pwd = new BasicAttribute("userpassword", hashedEncodedCredentials);
        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("person");
        oc.add("organizationalPerson");
        oc.add("inetOrgPerson");

        String userDN = String.format("uid=%s,dc=%s,dc=%s",
                user.getEmailAddress(),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            BasicAttributes entry = new BasicAttributes();
            entry.put(cn);
            entry.put(sn);
            entry.put(mail);
            entry.put(postalCode);
            entry.put(pwd);
            entry.put(oc);

            rootDirContext.createSubcontext(userDN, entry);

            addUserToGroup(realm, user.getEmailAddress(), roleType);

            return randomPassword;

        } catch (NamingException e)
        {
            LOG.error("Unable to define LDAP sub-context: {}", new Object[]{userDN});
            LOG.error(e.getMessage());
            throw new IllegalStateException("LDAP server was unable to create the user: " + e.getMessage());
        }
    }

    @Override
    public void sendPasswordResetEmail(IUser user)
    {
        try
        {
            ITemplateService templateService = context.getServiceFactory().getTemplateService();
            Configuration config = templateService.getConfiguration();

            Template subjectTemplate = config.getTemplate("PasswordResetEmailSubject.ftl");
            StringWriter subjectWriter = new StringWriter();
            templateService.merge(subjectTemplate, new HashMap(), subjectWriter);

            Map<String, Object> dataModel = new HashMap<>();

            String resetToken = createPwdResetDocument(user);

            dataModel.put("server", context.getConfiguration().getServerRoot());
            dataModel.put("urlPattern", context.getConfiguration().getUrlPattern());
            dataModel.put("resetToken", resetToken);
            dataModel.put("emailAddress", user.getEmailAddress());

            Template plainTemplate = config.getTemplate("PasswordResetEmailPlain.ftl");
            StringWriter plainWriter = new StringWriter();
            templateService.merge(plainTemplate, dataModel, plainWriter);

            Template htmlTemplate = config.getTemplate("PasswordResetEmailHtml.ftl");
            StringWriter htmlWriter = new StringWriter();
            templateService.merge(htmlTemplate, dataModel, htmlWriter);


            IEmailService emailService = context.getServiceFactory().getEmailService();
            emailService.sendEmail(user.getEmailAddress(),
                    subjectWriter.toString(),
                    plainWriter.toString(),
                    htmlWriter.toString());

            LOG.info("Password reset email invitation sent to email " +
                    user.getEmailAddress() + " with reset token " + resetToken);

        } catch (IOException e)
        {
            LOG.error("Unable to send password reset invitation email", e);
        }


    }

    @Override
    public void setPassword(IUser user, String newPassword)
    {
        String userDN = String.format("uid=%s,dc=%s,dc=%s",
                user.getEmailAddress(),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            Attribute mod = new BasicAttribute("userpassword",
                    CryptoUtil.digestThenEncodePasswordForLDAP("SHA", newPassword));
            ModificationItem[] mods = new ModificationItem[1];
            mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, mod);

            rootDirContext.modifyAttributes(userDN, mods);
        } catch (Exception e)
        {
            LOG.error("Unable to assign user password: {}", userDN);
            LOG.error(e.getMessage());
        }
    }

    @Override
    public void setPassword(IUser user, String resetToken, String newPassword)
    {
        String docDN = String.format("documentIdentifier=%s,uid=%s,dc=%s,dc=%s",
                DOCUMENT_IDENTIFIER_PASSWORD_RESET,
                user.getEmailAddress(),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        String userDN = String.format("uid=%s,dc=%s,dc=%s",
                user.getEmailAddress(),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            //
            // Find the users context in the LDAP hierarchy
            DirContext userContext = (DirContext) rootDirContext.lookup(docDN);

            // Now locate their POSTAL_CODE_ENABLED_HACK value
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> searchResults = userContext.search("", "(objectclass=*)", sc);

            if (searchResults.hasMoreElements())
            {
                SearchResult searchResult = searchResults.next();
                Attributes attributes = searchResult.getAttributes();

                Attribute attr = attributes.get("cn");
                String retrievedResetToken = attr.get().toString();

                if (resetToken.equals(retrievedResetToken))
                {
                    setPassword(user, newPassword);
                    rootDirContext.destroySubcontext(docDN);
                } else
                {
                    LOG.warn("Attempt to reset password using an invalid reset token: {}, {}", docDN, resetToken);
                }
            }

        } catch (NameNotFoundException e)
        {
            LOG.info("Attempt to reset password on user who didn't request self-service password reset: {}, {}",
                    docDN, resetToken);
        } catch (Exception e)
        {
            LOG.error("Unable to set password of user: {}", userDN);
            LOG.error(e.getMessage());
        }
    }

    @Override
    public void setEnabled(IUser user, boolean flag)
    {
        String userDN = String.format("uid=%s,dc=%s,dc=%s",
                user.getEmailAddress(),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            Attribute mod = new BasicAttribute(POSTAL_CODE_ENABLED_HACK, Boolean.toString(flag));
            ModificationItem[] mods = new ModificationItem[1];
            mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, mod);

            rootDirContext.modifyAttributes(userDN, mods);
        } catch (Exception e)
        {
            LOG.error("Unable to toggle user enabled flag: {}", userDN);
            LOG.error(e.getMessage());
        }
    }

    @Override
    public boolean isUserEnabled(IUser user)
    {
        boolean isEnabled = false;

        String userDN = String.format("uid=%s,dc=%s,dc=%s",
                user.getEmailAddress(),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            //
            // Find the users context in the LDAP hierarchy
            DirContext userContext = (DirContext) rootDirContext.lookup(userDN);

            // Now locate their POSTAL_CODE_ENABLED_HACK value
            SearchControls sc = new SearchControls();
            sc.setReturningAttributes(new String[]{POSTAL_CODE_ENABLED_HACK});
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> searchResults = userContext.search("", "(objectclass=*)", sc);

            if (searchResults.hasMoreElements())
            {
                SearchResult searchResult = searchResults.next();
                Attributes attributes = searchResult.getAttributes();

                Attribute attr = attributes.get(POSTAL_CODE_ENABLED_HACK);
                isEnabled = Boolean.parseBoolean(attr.get().toString());
            }

        } catch (NameNotFoundException e)
        {
            LOG.info("Attempt to check enabled status on a non-existent LDAP user: {}", userDN);
        } catch (Exception e)
        {
            LOG.error("Unable to check enabled state of user: {}", userDN);
            LOG.error(e.getMessage());
        }

        return isEnabled;
    }

    @Override
    public IAuthenticatedUser authenticate(ICredentials genericCredentials)
    {
        IAuthenticatedUser authenticatedUser;

        if (!(genericCredentials instanceof BasicCredentials))
        {
            throw new IllegalArgumentException("ICredentials is not a valid instance of BasicCredentials");
        }
        BasicCredentials credentials = (BasicCredentials) genericCredentials;

        String userDN = String.format("uid=%s,dc=%s,dc=%s",
                credentials.getUsername(),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        Properties p = new Properties();
        p.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        String url = String.format("ldap://%s:%d", directoryFactory.getHost(), directoryFactory.getPort());
        LOG.debug("LDAP url: ", url);

        p.setProperty(Context.PROVIDER_URL, url);
        p.setProperty(Context.SECURITY_PRINCIPAL, userDN);
        p.setProperty(Context.SECURITY_CREDENTIALS, credentials.getPassword());
        p.setProperty(Context.SECURITY_AUTHENTICATION, "simple");

        try
        {
            DirContext dirContext = new InitialDirContext(p);
            LOG.debug("Directory Context: " + dirContext.getNameInNamespace());

            //
            // If we get here, we know that the LDAP server authenticated the user/password combo..
            // Now, let's make sure the account is ENABLED
            //

            IUser user = context
                    .getDAOFactory()
                    .getUserDAO()
                    .lookupEmailAddress(credentials.getUsername());

            RoleType userRoleType = lookupUserRole(user);
            user.setRoleType(userRoleType);

            if (isUserEnabled(user))
            {
                authenticatedUser = new AuthenticatedUser(user);
            } else
            {
                LOG.info("The user {} was successfully authenticated with the provided password, but account disabled");
                throw new SecurityException("User account " + user.getEmailAddress() + " is DISABLED");
            }

        } catch (NamingException e)
        {
            LOG.info("Failed authentication attempt on username " + credentials.getUsername());
            throw new SecurityException(e);
        }

        return authenticatedUser;
    }

    @Override
    public IAuthenticatedUser exchangeToken(String bearerAccessToken)
    {
        throw new UnsupportedOperationException("Service doesn't support OAuth 2 token exchange in this release");
    }

    @Override
    public boolean isHealthy()
    {
        return (rootDirContext != null);
    }

    @Override
    public void start() throws Exception
    {
        Object dirConfigFactory = context.lookupExtension(ApacheDSServerExtension.EXTENSION_ID).getExtensionConfiguration();
        if (!(dirConfigFactory instanceof DirectoryConfiguration))
        {
            throw new IllegalStateException("Cannot case ApacheDS extension to instance of Directory Configuration");
        }

        //
        // The order of these two statements matter, as the directoryFactory is referenced in the dir ctx creation!
        //
        directoryFactory = (DirectoryConfiguration) dirConfigFactory;
        rootDirContext = createDirectoryContext();
    }

    @Override
    public void stop() throws Exception
    {
        if (rootDirContext != null)
        {
            rootDirContext.close();
        }
    }

    private boolean isUserInRole(IUser user, String roleDN) throws NamingException
    {
        boolean userInRoleFlag = false;

        DirContext roleContext = (DirContext) rootDirContext.lookup(roleDN);

        //
        // This code is functional, but there is probably a way to search thru the unique list
        // with the query instead of having to bring back the entire list of all email addresses
        //
        SearchControls sc = new SearchControls();
        sc.setReturningAttributes(new String[]{"uniqueMember"});
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> searchResults = roleContext.search("", "(objectclass=*)", sc);

        if (searchResults.hasMoreElements())
        {
            SearchResult searchResult = searchResults.next();
            Attributes attributes = searchResult.getAttributes();

            Attribute attr = attributes.get("uniqueMember");

            NamingEnumeration members = attr.getAll();

            while (members.hasMoreElements())
            {
                String member = members.next().toString();
                if (member.equalsIgnoreCase(String.format("uid=%s", user.getEmailAddress())))
                {
                    userInRoleFlag = true;
                    break;
                }
            }
        }

        return userInRoleFlag;
    }

    private DirContext createDirectoryContext() throws NamingException
    {
        String url = String.format("ldap://%s:%d", directoryFactory.getHost(), directoryFactory.getPort());
        LOG.info("LDAP url: ", url);

        Properties p = new Properties();
        p.setProperty(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        p.setProperty(Context.PROVIDER_URL, url);
        p.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        p.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        p.setProperty(Context.SECURITY_CREDENTIALS, directoryFactory.getServerPassword());

        return new InitialDirContext(p);
    }

    private void createGroup(String groupName, IRegistration registration)
    {
        Attribute initialAdminAccount = new BasicAttribute("uniqueMember", "uid=admin");

        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("groupOfUniqueNames");

        String groupDN = String.format("cn=%s,ou=%s,dc=%s,dc=%s",
                groupName,
                registration.getRealm().replace(',', ' '),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            BasicAttributes entry = new BasicAttributes();
            entry.put(initialAdminAccount);
            entry.put(oc);
            rootDirContext.createSubcontext(groupDN, entry);

        } catch (NamingException e)
        {
            LOG.error("Unable to define LDAP group sub-context: {}", new Object[]{groupDN});
            LOG.error(e.getMessage());
        }
    }

    private void createOrgUnit(IRegistration registration)
    {
        Attribute registeredAddress
                = new BasicAttribute("registeredAddress", registration.getAccount().getUrn());

        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("organizationalUnit");

        String parentEntryDN = String.format("ou=%s,dc=%s,dc=%s",
                registration.getRealm().replace(',', ' '),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            BasicAttributes entry = new BasicAttributes();
            entry.put(registeredAddress);
            entry.put(oc);

            rootDirContext.createSubcontext(parentEntryDN, entry);

        } catch (NamingException e)
        {
            LOG.error("Unable to define LDAP org sub-context: {}", new Object[]{parentEntryDN});
            LOG.error(e.getMessage());
        }
    }

    private String createPwdResetDocument(IUser user)
    {
        String resetToken = UUID.randomUUID().toString().replace("-", "");

        Attribute documentIdentifier = new BasicAttribute("documentIdentifier", DOCUMENT_IDENTIFIER_PASSWORD_RESET);
        Attribute cn = new BasicAttribute("cn", resetToken);

        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("document");

        String docDN = String.format("documentIdentifier=%s,uid=%s,dc=%s,dc=%s",
                DOCUMENT_IDENTIFIER_PASSWORD_RESET,
                user.getEmailAddress(),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            BasicAttributes entry = new BasicAttributes();
            entry.put(cn);
            entry.put(documentIdentifier);
            entry.put(oc);

            rootDirContext.createSubcontext(docDN, entry);

        } catch (NamingException e)
        {
            if (e.getMessage().contains("ENTRY_ALREADY_EXISTS"))
            {
                try
                {
                    rootDirContext.destroySubcontext(docDN);
                    resetToken = createPwdResetDocument(user);
                } catch (NamingException e1)
                {
                    LOG.error("Unable to remove stale LDAP directory sub-context: {}", docDN);
                    LOG.error(e.getMessage());
                }
            } else
            {
                LOG.error("Unable to create LDAP directory sub-context: {}", docDN);
                LOG.error(e.getMessage());
            }
        }

        return resetToken;
    }

    private void addUserToGroup(String realm, String emailAddress, RoleType roleType)
    {
        String cn = GROUP_USERS;
        if (roleType == RoleType.Administrator)
        {
            cn = GROUP_ADMINS;
        }

        String dn = String.format("cn=%s,ou=%s,dc=%s,dc=%s",
                cn,
                realm.replace(',', ' '),
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());

        try
        {
            Attribute mod = new BasicAttribute("uniqueMember", "uid=" + emailAddress);
            ModificationItem[] mods = new ModificationItem[1];
            mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod);

            rootDirContext.modifyAttributes(dn, mods);

        } catch (Exception e)
        {
            LOG.error("Unable to add user to group: {}", new Object[]{dn});
            LOG.error(e.getMessage());
        }

    }
}
