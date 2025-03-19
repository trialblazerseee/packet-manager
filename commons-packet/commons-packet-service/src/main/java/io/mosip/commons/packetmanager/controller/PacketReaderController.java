package io.mosip.commons.packetmanager.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.mosip.commons.packet.impl.PacketReaderImpl;
import io.mosip.commons.packet.util.PacketManagerLogger;
import io.mosip.commons.packetmanager.dto.SourceProcessDto;
import io.mosip.kernel.core.logger.spi.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.collect.Lists;

import io.mosip.commons.packet.dto.Document;
import io.mosip.commons.packet.dto.TagRequestDto;
import io.mosip.commons.packet.dto.TagResponseDto;
import io.mosip.commons.packet.facade.PacketReader;
import io.mosip.commons.packetmanager.dto.BiometricRequestDto;
import io.mosip.commons.packetmanager.dto.DocumentDto;
import io.mosip.commons.packetmanager.dto.FieldDto;
import io.mosip.commons.packetmanager.dto.FieldDtos;
import io.mosip.commons.packetmanager.dto.FieldResponseDto;
import io.mosip.commons.packetmanager.dto.InfoDto;
import io.mosip.commons.packetmanager.dto.InfoRequestDto;
import io.mosip.commons.packetmanager.dto.InfoResponseDto;
import io.mosip.commons.packetmanager.dto.ValidatePacketResponse;
import io.mosip.commons.packetmanager.service.PacketReaderService;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.util.DateUtils;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;

@RestController
@Tag(name = "packet-reader-controller", description = "Packet Reader Controller")
public class PacketReaderController {

    @Autowired
    private PacketReader packetReader;

    private static final Logger LOGGER = PacketManagerLogger.getLogger(PacketReaderController.class);


    @Autowired
    private PacketReaderService packetReaderService;
    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostsearchfield())")
    @ResponseFilter
    @PostMapping(path = "/searchField", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "searchField", description = "searchField", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
        public ResponseWrapper<FieldResponseDto> searchField(@RequestBody(required = true) RequestWrapper<FieldDto> fieldDto) {
        Long startTime = System.currentTimeMillis();
        SourceProcessDto sourceProcessDto = packetReaderService.getSourceAndProcess(fieldDto.getRequest().getId(),
                fieldDto.getRequest().getField(), fieldDto.getRequest().getSource(), fieldDto.getRequest().getProcess(), startTime);

        String resultField = sourceProcessDto == null ? null :
                packetReader.getField(fieldDto.getRequest().getId(),
                fieldDto.getRequest().getField(), sourceProcessDto.getSource(), sourceProcessDto.getProcess(), fieldDto.getRequest().getBypassCache(), startTime);
        ResponseWrapper<FieldResponseDto> response = new ResponseWrapper<FieldResponseDto>();
        Map<String, String> responseMap = new HashMap<>();
        responseMap.put(fieldDto.getRequest().getField(), resultField);
        FieldResponseDto fieldResponseDto = new FieldResponseDto(responseMap);

        response.setResponse(fieldResponseDto);
        LOGGER.info("THAM - End of /searchField for ID " + fieldDto.getRequest().getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
    }

    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostsearchfields())")
    @ResponseFilter
    @PostMapping(path = "/searchFields", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "searchFields", description = "searchFields", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    public ResponseWrapper<FieldResponseDto> searchFields(@RequestBody(required = true) RequestWrapper<FieldDtos> request) {
        FieldDtos fieldDtos = request.getRequest();
        Long startTime = System.currentTimeMillis();

        Map<String, String> resultFields = new HashMap<>();
        if ((fieldDtos.getSource()) == null) {
            for (String field : fieldDtos.getFields()) {
                SourceProcessDto sourceProcessDto = packetReaderService.getSourceAndProcess(fieldDtos.getId(),
                        field, fieldDtos.getSource(), fieldDtos.getProcess(), startTime);
                String value = sourceProcessDto == null ? null :
                        packetReader.getField(fieldDtos.getId(), field, sourceProcessDto.getSource(),
                        sourceProcessDto.getProcess(), fieldDtos.getBypassCache(), startTime);
                resultFields.put(field, value);
            }
        } else
            resultFields = packetReader.getFields(fieldDtos.getId(), fieldDtos.getFields(), fieldDtos.getSource(), fieldDtos.getProcess(), fieldDtos.getBypassCache(), startTime);
        FieldResponseDto resultField = new FieldResponseDto(resultFields);
        ResponseWrapper<FieldResponseDto> response = new ResponseWrapper<FieldResponseDto>();
        response.setResponse(resultField);
        LOGGER.info("THAM - End of /searchFields for ID " + fieldDtos.getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
    }

    @ResponseFilter
    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostdocument())")
    @PostMapping(path = "/document", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "getDocument", description = "getDocument", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    public ResponseWrapper<Document> getDocument(@RequestBody(required = true) RequestWrapper<DocumentDto> request) {
        DocumentDto documentDto = request.getRequest();
        Long startTime = System.currentTimeMillis();

        SourceProcessDto sourceProcessDto = packetReaderService.getSourceAndProcess(documentDto.getId(),
                documentDto.getDocumentName(), documentDto.getSource(), documentDto.getProcess(), startTime);
        Document document = sourceProcessDto == null ? null :
                packetReader.getDocument(documentDto.getId(), documentDto.getDocumentName(),
                sourceProcessDto.getSource(), sourceProcessDto.getProcess(), startTime);
        ResponseWrapper<Document> response = new ResponseWrapper<Document>();
        response.setResponse(document);
        LOGGER.info("THAM - End of /document for ID " + documentDto.getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
    }

    @ResponseFilter
    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostbiometrics())")
    @PostMapping(path = "/biometrics", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "getBiometrics", description = "getBiometrics", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    public ResponseWrapper<BiometricRecord> getBiometrics(@RequestBody(required = true) RequestWrapper<BiometricRequestDto> request) {
        BiometricRequestDto bioRequest = request.getRequest();
        Long startTime = System.currentTimeMillis();

        SourceProcessDto sourceProcessDto = packetReaderService.getSourceAndProcess(bioRequest.getId(),
                bioRequest.getPerson(), bioRequest.getSource(), bioRequest.getProcess(), startTime);
        List<String> modalities = bioRequest.getModalities() == null ? Lists.newArrayList() : bioRequest.getModalities();
        BiometricRecord responseDto = sourceProcessDto == null ? null :
                packetReader.getBiometric(bioRequest.getId(), bioRequest.getPerson(), modalities,
                sourceProcessDto.getSource(), sourceProcessDto.getProcess(), bioRequest.isBypassCache(), startTime);
        ResponseWrapper<BiometricRecord> response = getResponseWrapper();
        response.setResponse(responseDto);
        LOGGER.info("THAM - End of /biometrics for ID " + bioRequest.getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
    }

    @ResponseFilter
    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostmetainfo())")
    @PostMapping(path = "/metaInfo", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "getMetaInfo", description = "getMetaInfo", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    public ResponseWrapper<FieldResponseDto> getMetaInfo(@RequestBody(required = true) RequestWrapper<InfoDto> request) {
        InfoDto metaDto = request.getRequest();
        Long startTime = System.currentTimeMillis();

        SourceProcessDto sourceProcessDto = packetReaderService.getSourceAndProcess(metaDto.getId(), metaDto.getSource(), metaDto.getProcess(), startTime);
        Map<String, String> resultFields = packetReader.getMetaInfo(metaDto.getId(),
                sourceProcessDto.getSource(), sourceProcessDto.getProcess(), metaDto.getBypassCache(), startTime);
        FieldResponseDto resultField = new FieldResponseDto(resultFields);
        ResponseWrapper<FieldResponseDto> response = getResponseWrapper();
        response.setResponse(resultField);
        LOGGER.info("THAM - End of /metaInfo for ID " + metaDto.getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
    }

    @ResponseFilter
    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostaudits())")
    @PostMapping(path = "/audits", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "getAudits", description = "getAudits", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    public ResponseWrapper<List<FieldResponseDto>> getAudits(@RequestBody(required = true) RequestWrapper<InfoDto> request) {
        InfoDto metaDto = request.getRequest();
        Long startTime = System.currentTimeMillis();

        SourceProcessDto sourceProcessDto = packetReaderService.getSourceAndProcess(metaDto.getId(), metaDto.getSource(), metaDto.getProcess(), startTime);
        List<Map<String, String>> resultFields = packetReader.getAudits(metaDto.getId(),
                sourceProcessDto.getSource(), sourceProcessDto.getProcess(), metaDto.getBypassCache(), startTime);
        List<FieldResponseDto> resultField = new ArrayList<>();
        if (resultFields != null && !resultFields.isEmpty()) {
            resultFields.stream().forEach(e -> {
                FieldResponseDto fieldResponseDto = new FieldResponseDto(e);
                resultField.add(fieldResponseDto);
            });
        }
        ResponseWrapper<List<FieldResponseDto>> response = getResponseWrapper();
        response.setResponse(resultField);
        LOGGER.info("THAM - End of /audits for ID " + metaDto.getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
    }

    @ResponseFilter
    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostvalidatepacket())")
    @PostMapping(path = "/validatePacket", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "validatePacket", description = "validatePacket", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    public ResponseWrapper<ValidatePacketResponse> validatePacket(@RequestBody(required = true) RequestWrapper<InfoDto> request) {
        InfoDto metaDto = request.getRequest();
        Long startTime = System.currentTimeMillis();
        SourceProcessDto sourceProcessDto = packetReaderService.getSourceAndProcess(metaDto.getId(), metaDto.getSource(), metaDto.getProcess(), startTime);
        boolean resultFields = packetReader.validatePacket(metaDto.getId(), sourceProcessDto.getSource(), sourceProcessDto.getProcess(), startTime);
        ResponseWrapper<ValidatePacketResponse> response = getResponseWrapper();
        response.setResponse(new ValidatePacketResponse(resultFields));
        LOGGER.info("THAM - End of /validatePacket for ID " + metaDto.getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
    }

    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostgettags())")
    @ResponseFilter
	@PostMapping(path = "/getTags", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "getTags", description = "getTags", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	public ResponseWrapper<TagResponseDto> getTags(
			@RequestBody(required = true) RequestWrapper<TagRequestDto> request) {
        Long startTime = System.currentTimeMillis();
		TagResponseDto tagResponseDto = packetReaderService.getTags(request.getRequest(), startTime);
		ResponseWrapper<TagResponseDto> response = getResponseWrapper();
		response.setResponse(tagResponseDto);
        LOGGER.info("THAM - End of /getTags for ID " + request.getRequest().getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
	}

    @ResponseFilter
    @PreAuthorize("hasAnyRole(@authorizedRoles.getPostinfo())")
    @PostMapping(path = "/info", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "info", description = "info", tags = { "packet-reader-controller" })
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "201", description = "Created", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
            @ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
    public ResponseWrapper<InfoResponseDto> info(@RequestBody(required = true) RequestWrapper<InfoRequestDto> request) {
        String id = request.getRequest().getId();
        Long startTime = System.currentTimeMillis();

        InfoResponseDto resultFields = null;
        if (id != null && !id.isEmpty())
            resultFields = packetReaderService.info(id, startTime);
        ResponseWrapper<InfoResponseDto> response = getResponseWrapper();
        response.setResponse(resultFields);
        LOGGER.info("THAM - End of /info for ID " + request.getRequest().getId() + " " + (System.currentTimeMillis() - startTime) + "ms ");

        return response;
    }

    private ResponseWrapper getResponseWrapper() {
        ResponseWrapper<Object> response = new ResponseWrapper<>();
        response.setId("mosip.registration.packet.reader");
        response.setVersion("v1");
        response.setResponsetime(DateUtils.getUTCCurrentDateTime());
        return response;
    }
}
