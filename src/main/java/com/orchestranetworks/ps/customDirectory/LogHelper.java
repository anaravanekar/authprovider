package com.orchestranetworks.ps.customDirectory;

import com.keysight.authprovider.custom.LoggerCustomDirectory;
import com.onwbp.boot.LoggingCategoryHelper;
import com.onwbp.org.apache.log4j.Category;
import com.orchestranetworks.service.LoggingCategory;

public class LogHelper {
	public final static LoggingCategory customDirectoryLog = LoggingCategoryHelper.getLoggingCategory(Category.getInstance("log.CustomDirectory"));
	public final static LoggingCategory customDirectoryPerformanceLog = LoggingCategoryHelper.getLoggingCategory(Category.getInstance("log.CustomDirectory.performance"));
}
