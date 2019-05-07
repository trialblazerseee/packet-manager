package io.mosip.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The Class UinCardGeneratorImpl.
 * 
 * @author M1048358 Alok
 */
@Component
public class UinCardGeneratorImpl implements UinCardGenerator<ByteArrayOutputStream> {

	/** The pdf generator. */
	@Autowired
	private PDFGenerator pdfGenerator;

	/** The reg proc logger. */
	private static Logger logger = Logger.getLogger(UinCardGeneratorImpl.class);

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.registration.processor.core.spi.uincardgenerator.UinCardGenerator#
	 * generateUinCard(java.io.InputStream,
	 * io.mosip.registration.processor.core.constant.UinCardType)
	 */
	@Override
	public ByteArrayOutputStream generateUinCard(InputStream in, UinCardType type) {
		ByteArrayOutputStream out = null;
		try {
			out = (ByteArrayOutputStream) pdfGenerator.generate(in);
		} catch (IOException e) {
			logger.error("exception occurred ",e);
		}

		return out;
	}

}
