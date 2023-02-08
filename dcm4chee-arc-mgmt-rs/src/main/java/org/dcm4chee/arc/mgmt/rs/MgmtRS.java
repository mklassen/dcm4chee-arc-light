package org.dcm4chee.arc.mgmt.rs;

import org.dcm4che3.conf.api.DicomConfiguration;
import org.dcm4che3.conf.ldap.LdapDicomConfiguration;

import org.dcm4che3.net.Device;
import org.jboss.resteasy.annotations.cache.NoCache;

import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.context.spi.Contextual;
import jakarta.enterprise.context.spi.CreationalContext;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.inject.Inject;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Hashtable;

@RequestScoped
@Path("/mgmt")
public class MgmtRS {

    @Inject
    private BeanManager manager;

    @Inject
    private Device device;

    @GET
    @NoCache
    @Path("access")
    @Produces("application/json")
    public Response access() {

        // Unfortunately the configuration does not have public accessors for the desired values
        // Therefore we need to use reflect to actually get the LDAP configuration values
        Hashtable<?,?> map;
        String aetsRegistryDN;
        String devicesDN;
        String configurationDN;

        try {
            Bean<?> bean = manager.getBeans(DicomConfiguration.class).iterator().next();
            if (!bean.getBeanClass().getName().equals("org.dcm4chee.arc.conf.ldap.LdapArchiveConfigurationFactory"))
            {
                return Response.status(Response.Status.METHOD_NOT_ALLOWED).entity("Ldap configuration not used").build();
            }

            final CreationalContext<LdapDicomConfiguration> ctx = manager.createCreationalContext(null);
            @SuppressWarnings("unchecked") LdapDicomConfiguration ldap = manager.getContext(bean.getScope()).get((Contextual<LdapDicomConfiguration>) bean, ctx);

            // LdapDicomConfiguration comes from a separate library org.dcm4che3.conf.ldap
            // The LDAP connection is handled by a DirContext wrapped inside a private class
            // org.dcm4che3.conf.ldap.ReconnectDirContext;
            // The private field ctx stores the instance of ReconnectDirContext
            // Use reflect to get a generic object reference to the ReconnectDirContext instance
            Field field = LdapDicomConfiguration.class.getDeclaredField("ctx");
            field.setAccessible(true);
            Object obj = field.get(ldap);

            // ReconnectDirContext has a public method getDirCtx with returns DirContext
            // Use reflect to access this public method because ReconnectDirContext is private
            Method method = obj.getClass().getMethod("getDirCtx");
            method.setAccessible(true);
            DirContext ctx2 = (DirContext) method.invoke(obj);

            // Get the environment, which includes the settings to access the LDAP server
            map = ctx2.getEnvironment();

            // Unfortunately LdapDicomConfiguration does not provide public accessors to all DNs
            // Use reflection to access the private field aetsRegistryDN
            field = LdapDicomConfiguration.class.getDeclaredField("aetsRegistryDN");
            field.setAccessible(true);
            aetsRegistryDN = (String)field.get(ldap);

            // Use reflection to access the private field devicesDN
            field = LdapDicomConfiguration.class.getDeclaredField("devicesDN");
            field.setAccessible(true);
            devicesDN = (String)field.get(ldap);

            configurationDN = ldap.getConfigurationDN();
        }
        catch (NoSuchFieldException | IllegalAccessException | NoSuchMethodException | InvocationTargetException |
               NamingException e)
        {
            return Response.status(Response.Status.METHOD_NOT_ALLOWED).entity(e.toString()).build();
        }
        catch (Exception e)
        {
            return Response.status(Response.Status.METHOD_NOT_ALLOWED).entity(e.toString()).build();
        }

        String deviceDN = "dicomDeviceName=" + device.getDeviceName() + "," + devicesDN;

        return Response.ok("{\"ldapUrl\":\"" + map.get(javax.naming.Context.PROVIDER_URL) +
                "\",\"userDN\":\"" + map.get(javax.naming.Context.SECURITY_PRINCIPAL) +
                "\",\"userPassword\":\"" + map.get(javax.naming.Context.SECURITY_CREDENTIALS) +
                "\",\"deviceDN\":\"" + deviceDN +
                "\",\"devicesDN\":\"" + devicesDN +
                "\",\"configurationDN\":\"" + configurationDN +
                "\",\"aetsRegistryDN\":\"" + aetsRegistryDN +
             "\"}", MediaType.APPLICATION_JSON_TYPE).build();
    }
}
