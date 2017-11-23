package com.keysight.authprovider.custom;

import com.onwbp.adaptation.AdaptationHome;
import com.orchestranetworks.service.directory.Directory;
import com.orchestranetworks.service.directory.DirectoryDefaultFactory;

/* Default factory for custom directory 
 * @see com.orchestranetworks.service.directory.DirectoryDefaultFactory#createDirectory(com.onwbp.adaptation.AdaptationHome)
 */
public class CustomDirectoryFactory extends DirectoryDefaultFactory {
	/* Create a custom directory with an external directory. 
	 * A simple extension of the DirectoryDefaultFactory.
	 * 
	 * @see com.orchestranetworks.service.directory.DirectoryDefaultFactory#createDirectory(com.onwbp.adaptation.AdaptationHome)
	 */
	public CustomDirectoryFactory(){
		super();
	}
	@Override
	public Directory createDirectory(AdaptationHome aHome) throws Exception {
		return new CustomDirectory(aHome);
	}
}
