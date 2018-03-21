package com.orchestranetworks.ps.customDirectory;

import com.keysight.authprovider.custom.LoggerCustomDirectory;
import com.onwbp.adaptation.AdaptationHome;
import com.orchestranetworks.service.directory.Directory;
import com.orchestranetworks.service.directory.DirectoryFactory;

import java.util.logging.Logger;

public class HistoryCustomDirectoryFactory extends DirectoryFactory {

	private final static Logger LOGGER = LoggerCustomDirectory.getLogger();

	@Override
	public Directory createDirectory(final AdaptationHome aHome) {
		final Directory dir = new HistoryCustomDirectory(aHome);
		LOGGER.info("Initialised HistoryCustomDirectory");
		return dir;
	}

}
