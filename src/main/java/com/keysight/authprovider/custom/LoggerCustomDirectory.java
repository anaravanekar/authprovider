package com.keysight.authprovider.custom;

import java.util.logging.Logger;

public final class LoggerCustomDirectory {
	
	private final static Logger logger = Logger.getLogger("customDirectory");
	private LoggerCustomDirectory(){

	}
	
	public static final Logger getLogger(){
		return logger;
	}
}
