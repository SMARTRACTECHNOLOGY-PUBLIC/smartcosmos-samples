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

import com.fasterxml.jackson.annotation.JsonProperty;
import net.smartcosmos.platform.base.AbstractSmartCosmosExtensionConfiguration;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

public class DirectoryConfiguration extends AbstractSmartCosmosExtensionConfiguration
{
    @NotNull
    @JsonProperty
    private String workingDirectory;

    @NotNull
    @JsonProperty
    private String instanceId;

    @NotNull
    @JsonProperty
    private String serverPassword;

    @Min(1025)
    @JsonProperty
    private Integer port = 1400;

    @NotNull
    @JsonProperty
    private String host;

    @NotNull
    @JsonProperty
    private String partitionId;

    @NotNull
    @JsonProperty
    private String topLevelDomain;

    @NotNull
    @JsonProperty
    private String secondLevelDomain;

    @NotNull
    @JsonProperty
    private String organization;

    public String getOrganization()
    {
        return organization;
    }

    public String getInstanceId()
    {
        return instanceId;
    }

    public String getWorkingDirectory()
    {
        return workingDirectory;
    }

    public String getPartitionId()
    {
        return partitionId;
    }

    public Integer getPort()
    {
        return port;
    }

    public String getServerPassword()
    {
        return serverPassword;
    }

    public String getTopLevelDomain()
    {
        return topLevelDomain;
    }

    public String getSecondLevelDomain()
    {
        return secondLevelDomain;
    }

    public String getHost()
    {
        return host;
    }

    public void setHost(String host)
    {
        this.host = host;
    }

    public void setWorkingDirectory(String workingDirectory)
    {
        this.workingDirectory = workingDirectory;
    }

    public void setInstanceId(String instanceId)
    {
        this.instanceId = instanceId;
    }

    public void setServerPassword(String serverPassword)
    {
        this.serverPassword = serverPassword;
    }

    public void setPort(Integer port)
    {
        this.port = port;
    }

    public void setPartitionId(String partitionId)
    {
        this.partitionId = partitionId;
    }

    public void setTopLevelDomain(String topLevelDomain)
    {
        this.topLevelDomain = topLevelDomain;
    }

    public void setSecondLevelDomain(String secondLevelDomain)
    {
        this.secondLevelDomain = secondLevelDomain;
    }

    public void setOrganization(String organization)
    {
        this.organization = organization;
    }
}
