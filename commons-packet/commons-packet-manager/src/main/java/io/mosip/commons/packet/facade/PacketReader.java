package io.mosip.commons.packet.facade;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;

import io.mosip.commons.khazana.dto.ObjectDto;
import io.mosip.commons.packet.dto.Document;
import io.mosip.commons.packet.exception.NoAvailableProviderException;
import io.mosip.commons.packet.keeper.PacketKeeper;
import io.mosip.commons.packet.spi.IPacketReader;
import io.mosip.commons.packet.util.PacketHelper;
import io.mosip.commons.packet.util.PacketManagerLogger;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.core.logger.spi.Logger;

/**
 * The packet Reader facade
 */
@RefreshScope
@Component
public class PacketReader {

    private static final Logger LOGGER = PacketManagerLogger.getLogger(PacketReader.class);

    @Autowired(required = false)
    @Qualifier("referenceReaderProviders")
    @Lazy
    private List<IPacketReader> referenceReaderProviders;

	@Autowired
	private PacketKeeper packetKeeper;

    private ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Get a field from identity file
     *
     * @param id      : the registration id
     * @param field   : field name to search
     * @param source  : the source packet. If not present return default
     * @param process : the process
     * @return String field
     */
    @PreAuthorize("hasRole('DATA_READ')")
    public String getField(String id, String field, String source, String process, boolean bypassCache) {
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getField for fields : " + field + " source : " + source + " process : " + process + " Cache : " + bypassCache);
        String value;
        if (bypassCache)
            value = getProvider(source, process).getField(id, field, source, process);
        else {
            Optional<Object> optionalValue = getAllFields(id, source, process).entrySet().stream().filter(m-> m.getKey().equalsIgnoreCase(field) && m.getValue()!=null).map(m -> m.getValue()).findAny();
            value = optionalValue.isPresent() ? optionalValue.get().toString() : null;
        }
        return value;
    }

    /**
     * Get fields from identity file
     *
     * @param id      : the registration id
     * @param fields  : fields to search
     * @param source  : the source packet. If not present return default
     * @param process : the process
     * @return Map fields
     */
    @PreAuthorize("hasRole('DATA_READ')")
    public Map<String, String> getFields(String id, List<String> fields, String source, String process, boolean bypassCache) {
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getFields for fields : " + fields.toString() + " source : " + source + " process : " + process+ " Cache : " + bypassCache);
        Map<String, String> values;
        if (bypassCache)
            values = getProvider(source, process).getFields(id, fields, source, process);
        else {
            values = getAllFields(id, source, process).entrySet()
                    .stream().filter(m -> fields.contains(m.getKey())).collect(Collectors.toMap(m -> m.getKey(), m -> m.getValue() != null ? m.getValue().toString() : null));
        }
        return values;
    }

    /**
     * Get document by registration id, document name, source and process
     *
     * @param id           : the registration id
     * @param documentName : the document name
     * @param source       : the source packet. If not present return default
     * @param process      : the process
     * @return Document : document information
     */
    @PreAuthorize("hasRole('DOCUMENT_READ')")
    @Cacheable(value = "packets", key = "'documents'.concat('-').concat(#id).concat('-').concat(#documentName).concat('-').concat(#source).concat('-').concat(#process)")
    public Document getDocument(String id, String documentName, String source, String process) {
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getDocument for documentName : " + documentName + " source : " + source + " process : " + process);
        Long startTime = System.nanoTime();
        Document document=  getProvider(source, process).getDocument(id, documentName, source, process);
        LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getDocument - Object Reading for field : " + documentName + " source : " + source + " process : " + process + " From Object Store. Response Time in Seconds : " + TimeUnit.MILLISECONDS.convert(System.nanoTime()-startTime, TimeUnit.NANOSECONDS));
        return document;
    }

    /**
     * Get biometric information by registration id, document name, source and process
     *
     * @param id         : the registration id
     * @param person     : The person (ex - applicant, operator, supervisor, introducer etc)
     * @param modalities : list of biometric modalities
     * @param source     : the source packet. If not present return default
     * @param process    : the process
     * @return BiometricRecord : the biometric record
     */
    @PreAuthorize("hasRole('BIOMETRIC_READ')")
    @Cacheable(value = "packets", key = "'biometrics'.concat('-').#id.concat('-').concat(#person).concat('-').concat(#modalities).concat('-').concat(#source).concat('-').concat(#process)", condition = "#bypassCache == false")
    public BiometricRecord getBiometric(String id, String person, List<String> modalities, String source, String process, boolean bypassCache) {
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getBiometric for source : " + source + " process : " + process);
        Long startTime = System.nanoTime();
        BiometricRecord biometricRecord =  getProvider(source, process).getBiometric(id, person, modalities, source, process);
        try {
            LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                    "getBiometric - Object Reading for field : " + person + "[" + objectMapper.writeValueAsString(modalities) + "]"  + " source : " + source + " process : " + process + " From Object Store. Response Time in Seconds : " + TimeUnit.MILLISECONDS.convert(System.nanoTime()-startTime, TimeUnit.NANOSECONDS));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return biometricRecord;

    }

    /**
     * Get packet meta information by registration id, source and process
     *
     * @param id      : the registration id
     * @param source  : the source packet. If not present return default
     * @param process : the process
     * @return Map fields
     */
    @PreAuthorize("hasRole('METADATA_READ')")
    @Cacheable(value = "packets", key = "{'metaInfo'.concat('-').concat(#id).concat('-').concat(#source).concat('-').concat(#process)}", condition = "#bypassCache == false")
    public Map<String, String> getMetaInfo(String id, String source, String process, boolean bypassCache) {
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getMetaInfo for source : " + source + " process : " + process);
        Long startTime = System.nanoTime();
        Map<String, String> metaMap=  getProvider(source, process).getMetaInfo(id, source, process);
        LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getMetaInfo - Object Reading"  + " source : " + source + " process : " + process + " From Object Store. Response Time in Seconds : " + TimeUnit.MILLISECONDS.convert(System.nanoTime()-startTime, TimeUnit.NANOSECONDS));
        return metaMap;

    }

    /**
     * Get all field names from identity object
     *
     * @param id
     * @param source
     * @param process
     * @return
     */
    @PreAuthorize("hasRole('DATA_READ')")
    public List<ObjectDto> info(String id) {
//        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
//                "info called");
        Long startTime = System.nanoTime();
        List<ObjectDto> objectList =  packetKeeper.getAll(id);
        LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "info - Object Reading From Object Store. Response Time in Seconds : " + TimeUnit.MILLISECONDS.convert(System.nanoTime()-startTime, TimeUnit.NANOSECONDS));
        return objectList;
    }

    /**
     * Get all field names from identity object
     *
     * @param id
     * @param source
     * @param process
     * @return
     */
    @PreAuthorize("hasRole('DATA_READ')")
    public Set<String> getAllKeys(String id, String source, String process) {
//        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
//                "getAllKeys for source : " + source + " process : " + process);
        return getProvider(source, process).getAll(id, source, process).keySet();
    }

    /**
     * Get all fields from packet by id, source and process
     *
     * @param id      : the registration id
     * @param source  : the source packet. If not present return default
     * @param process : the process
     * @return Map fields
     */
    private Map<String, Object> getAllFields(String id, String source, String process) {
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getAllFields for source : " + source + " process : " + process);
        return getProvider(source, process).getAll(id, source, process);
    }

    /**
     * Get all fields from packet by id, source and process
     *
     * @param id      : the registration id
     * @param source  : the source packet. If not present return default
     * @param process : the process
     * @return Map fields
     */
    @Cacheable(value = "packets", key = "{#id.concat('-').concat(#source).concat('-').concat(#process)}", condition = "#bypassCache == false")
    public List<Map<String, String>> getAudits(String id, String source, String process, boolean bypassCache) {
        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getAudits for source : " + source + " process : " + process);
        Long startTime = System.nanoTime();
        List<Map<String, String>> map =  getProvider(source, process).getAuditInfo(id, source, process);
        LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getAudits - Object Reading"  + " source : " + source + " process : " + process + " From Object Store. Response Time in Seconds : " + TimeUnit.MILLISECONDS.convert(System.nanoTime()-startTime, TimeUnit.NANOSECONDS));
        return map;
    }

    @Cacheable(value = "tags", key = "{#id}")
    public  Map<String, String>  getTags(String id) {
        Long startTime = System.nanoTime();
        Map<String, String> tags = packetKeeper.getTags(id);
        LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "getTags - Object Reading  From Object Store. Response Time in Seconds : " + TimeUnit.MILLISECONDS.convert(System.nanoTime()-startTime, TimeUnit.NANOSECONDS));
        return tags;
    }

    public boolean validatePacket(String id, String source, String process) {
        Long startTime = System.nanoTime();
        boolean valid =  getProvider(source, process).validatePacket(id, source, process);
        LOGGER.debug(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, id,
                "validatePacket - Object Reading"  + " source : " + source + " process : " + process + " From Object Store. Response Time in Seconds : " + TimeUnit.MILLISECONDS.convert(System.nanoTime()-startTime, TimeUnit.NANOSECONDS));
        return valid;
    }

    private IPacketReader getProvider(String source, String process) {
//        LOGGER.info(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
//                "getProvider for source : " + source + " process : " + process);
        IPacketReader provider = null;
        if (referenceReaderProviders != null && !referenceReaderProviders.isEmpty()) {
            Optional<IPacketReader> refProvider = referenceReaderProviders.stream().filter(refPr ->
                    (PacketHelper.isSourceAndProcessPresent(refPr.getClass().getName(), source, process, PacketHelper.Provider.READER))).findAny();
            if (refProvider.isPresent() && refProvider.get() != null)
                provider = refProvider.get();
        }

        if (provider == null) {
            LOGGER.error(PacketManagerLogger.SESSIONID, PacketManagerLogger.REGISTRATIONID, null,
                    "No available provider found for source : " + source + " process : " + process);
            throw new NoAvailableProviderException();
        }

        return provider;
    }

}
