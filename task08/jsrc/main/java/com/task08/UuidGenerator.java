package com.task08;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.syndicate.deployment.annotations.lambda.LambdaHandler;
import com.syndicate.deployment.annotations.events.RuleEventSource;
import com.syndicate.deployment.model.RetentionSetting;
import com.syndicate.deployment.annotations.environment.EnvironmentVariable;
import com.syndicate.deployment.annotations.environment.EnvironmentVariables;
import java.time.Instant;
import java.util.*;
import java.nio.charset.StandardCharsets;

@LambdaHandler(
		lambdaName = "uuid_generator",
		roleName = "uuid_generator-role",
		isPublishVersion = true,
		aliasName = "${lambdas_alias_name}",
		logsExpiration = RetentionSetting.SYNDICATE_ALIASES_SPECIFIED
)
@RuleEventSource(targetRule = "uuid_trigger")
@EnvironmentVariables(value = {
		@EnvironmentVariable(key = "target_bucket", value = "${target_bucket}")
})
public class UuidGenerator implements RequestHandler<Object, Map<String, Object>> {

	private static final String BUCKET_NAME = System.getenv("target_bucket");  // "uuid-storage"
	private final AmazonS3 s3Client = AmazonS3ClientBuilder.defaultClient();
	private final ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public Map<String, Object> handleRequest(Object request, Context context) {
		try {
			// Generate 10 random UUIDs
			List<String> uuidList = generateUUIDs(10);

			// Generate ISO Timestamp for filename
			String timestamp = Instant.now().toString();

			// Prepare JSON content
			Map<String, Object> jsonContent = new HashMap<>();
			jsonContent.put("ids", uuidList);
			String jsonString = objectMapper.writeValueAsString(jsonContent);

			// Upload to S3
			s3Client.putObject(BUCKET_NAME, timestamp, jsonString);

			// Log and return response
			System.out.println("File uploaded: " + timestamp);
			return createResponse(200, "File stored in S3: " + timestamp);
		} catch (Exception e) {
			e.printStackTrace();
			return createResponse(500, "Error: " + e.getMessage());
		}
	}

	private List<String> generateUUIDs(int count) {
		List<String> uuids = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			uuids.add(UUID.randomUUID().toString());
		}
		return uuids;
	}

	private Map<String, Object> createResponse(int statusCode, String message) {
		Map<String, Object> response = new HashMap<>();
		response.put("statusCode", statusCode);
		response.put("body", message);
		return response;
	}
}
