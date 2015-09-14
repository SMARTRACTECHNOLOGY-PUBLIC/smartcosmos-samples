package net.smartcosmos.sample.extensions.server.apacheds;

/*
 * *#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
 * SMART COSMOS Sample - Server Extension - ApacheDS
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

import com.google.common.collect.Lists;
import net.smartcosmos.platform.base.AbstractServerExtension;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.entry.ServerEntry;
import org.apache.directory.server.core.partition.Partition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.xdbm.Index;
import org.apache.directory.shared.ldap.entry.EntryAttribute;
import org.apache.directory.shared.ldap.entry.Modification;
import org.apache.directory.shared.ldap.entry.ModificationOperation;
import org.apache.directory.shared.ldap.entry.client.ClientModification;
import org.apache.directory.shared.ldap.entry.client.DefaultClientAttribute;
import org.apache.directory.shared.ldap.exception.LdapNameNotFoundException;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class ApacheDSServerExtension extends AbstractServerExtension<DirectoryConfiguration>
{

    public static final String LDAP_ATTRIB_USER_PASSWORD = "userpassword";

    public static final String EXTENSION_ID = "db912ff2-75e6-404a-9264-1b1503b19982";

    private static final Logger LOG = LoggerFactory.getLogger(ApacheDSServerExtension.class);

    /**
     * The directory directoryService.
     */
    private DirectoryService directoryService;

    private LdapServer ldapServer;

    public ApacheDSServerExtension()
    {
        super(EXTENSION_ID, "ApacheDS Server Extension", DirectoryConfiguration.class);
    }

    @Override
    protected void initialize(DirectoryConfiguration extensionConfiguration) throws Exception
    {
        if (extensionConfiguration.isEnabled())
        {

            // Initialize the LDAP directoryService
            directoryService = new DefaultDirectoryService();

            // Define LDAP server behaviors
            directoryService.getChangeLog().setEnabled(false);
            directoryService.setDenormalizeOpAttrsEnabled(true);
            directoryService.setAllowAnonymousAccess(true);
            directoryService.setInstanceId(extensionConfiguration.getInstanceId());

            // Add partition to the directory
            Partition partition = addPartition(extensionConfiguration);

            defineWorkingDirectory(extensionConfiguration.getWorkingDirectory());

            ldapServer = new LdapServer();
            ldapServer.setTransports(new TcpTransport(extensionConfiguration.getPort()));
            ldapServer.setDirectoryService(directoryService);

            // Startup the directory service
            LOG.info("Starting up the default directory service...");

            LOG.warn("*********************************************************************************");
            LOG.warn("*** NOTE: An ERROR log entry will be reported by ApacheDS that can be ignored ***");
            LOG.warn("*********************************************************************************");
            LOG.warn("ApacheDS may report ERROR about DefaultAttributeTypeRegistry w/ OID 2.5.4.16 not registered");
            LOG.warn("This error was confirmed by members of the Apache Directory Services team to be innocuous!");
            LOG.warn("The log entry was inappropriately categorized as an ERROR in this release of Apache Directory");
            LOG.warn("*********************************************************************************");

            try
            {
                directoryService.startup();

                // Inject the root entry if it does not already exist
                try
                {
                    LdapDN suffixDN = partition.getSuffixDn();
                    directoryService.getAdminSession().lookup(suffixDN);
                } catch (LdapNameNotFoundException e)
                {
                    LOG.info("Injecting root for {}", getPartitionDN(extensionConfiguration));
                    LdapDN ldapDn = new LdapDN(getPartitionDN(extensionConfiguration));
                    ServerEntry serverEntry = directoryService.newEntry(ldapDn);
                    serverEntry.add("objectClass", "top", "domain", "extensibleObject");
                    serverEntry.add("dc", extensionConfiguration.getSecondLevelDomain());
                    serverEntry.add("o", extensionConfiguration.getOrganization());
                    directoryService.getAdminSession().add(serverEntry);
                }

                ldapServer.start();

                confirmOrUpdateAdminPassword(extensionConfiguration);

            } catch (Exception e)
            {
                LOG.error("Unable to successfully start directory service: " + e.getMessage());
                LOG.error("Does the process have write-access to the working directory specified in the YML file?");

                //
                // If we don't re-throw this, Dropwizard continues to start as if there were no problem!
                throw e;
            }
        } else
        {
            LOG.info("Embedded directory service is disabled in the YML configuration file");
        }
    }

    @Override
    public void stop() throws Exception
    {
        LOG.info("Shutting down the LDAP service...");
        ldapServer.stop();

        LOG.info("Shutting down the directory service...");
        directoryService.shutdown();
    }

    public DirectoryService getDirectoryService()
    {
        return directoryService;
    }

    public void replaceAttribute(String dn, String attName, String value) throws Exception
    {
        LdapDN ldapDN = new LdapDN(dn);
        EntryAttribute attribute = new DefaultClientAttribute(attName, value);
        Modification m = new ClientModification(ModificationOperation.REPLACE_ATTRIBUTE, attribute);
        List<Modification> l = Lists.newArrayList(m);
        directoryService.getAdminSession().modify(ldapDN, l);
    }

    private void confirmOrUpdateAdminPassword(DirectoryConfiguration directoryFactory) throws Exception
    {
        replaceAttribute("uid=admin,ou=system", LDAP_ATTRIB_USER_PASSWORD, directoryFactory.getServerPassword());
        LOG.info("Default admin account password successfully set to the password defined in the YML file");
    }

    private void defineWorkingDirectory(String path)
    {
        File workingDirectory = new File(path);
        if (!workingDirectory.exists())
        {
            // noinspection ResultOfMethodCallIgnored
            boolean result = workingDirectory.mkdirs();
            if (!result)
            {
                LOG.debug("Could not create working directory path");
            }
        }
        directoryService.setWorkingDirectory(workingDirectory);
    }

    private String getPartitionDN(DirectoryConfiguration directoryFactory)
    {
        return String.format("dc=%s,dc=%s",
                directoryFactory.getSecondLevelDomain(),
                directoryFactory.getTopLevelDomain());
    }

    private Partition addPartition(DirectoryConfiguration directoryFactory) throws Exception
    {
        LOG.info("Adding partition for " + getPartitionDN(directoryFactory));

        JdbmPartition partition = new JdbmPartition();
        partition.setId(directoryFactory.getPartitionId());
        partition.setSuffix(getPartitionDN(directoryFactory));
        partition.setCacheSize(1000);
        partition.init(directoryService);

        Set<Index<?, ServerEntry>> indexAttribute = new HashSet<>();
        indexAttribute.add(new JdbmIndex<>("objectClass"));
        indexAttribute.add(new JdbmIndex<>("o"));
        partition.setIndexedAttributes(indexAttribute);

        directoryService.addPartition(partition);
        return partition;
    }
}
