package org.dependencytrack.resources;

import alpine.logging.Logger;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class GlobalExceptionHandler implements ExceptionMapper<Exception>
{
    private static final Logger LOGGER = Logger.getLogger(GlobalExceptionHandler.class);

    @Override
    public Response toResponse(Exception exception)
    {
        LOGGER.error("Uncaught internal server error", exception);

        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Uncaught internal server error").build();
    }
}