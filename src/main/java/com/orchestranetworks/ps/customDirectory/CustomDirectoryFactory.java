package com.orchestranetworks.ps.customDirectory;

import com.onwbp.adaptation.AdaptationHome;
import com.orchestranetworks.service.directory.Directory;
import com.orchestranetworks.service.directory.DirectoryDefaultFactory;

public class CustomDirectoryFactory extends DirectoryDefaultFactory {
	
	@Override
	public Directory createDirectory(final AdaptationHome aHome) throws Exception{
		final Directory dir = new CustomDirectory(aHome);
		System.out.println("Initialised Custom Directory");
		return dir;
	}
}
