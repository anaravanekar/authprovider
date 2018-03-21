package com.orchestranetworks.ps.historycustomdirectory;

import com.keysight.authprovider.custom.LoggerCustomDirectory;
import com.onwbp.adaptation.Adaptation;
import com.onwbp.adaptation.AdaptationTable;
import com.orchestranetworks.schema.Path;
import com.orchestranetworks.schema.trigger.*;
import com.orchestranetworks.service.OperationException;
import com.orchestranetworks.service.ProcedureContext;
import com.orchestranetworks.service.ValueContextForUpdate;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class UsersTrigger extends TableTrigger {

	private final static Logger LOGGER = LoggerCustomDirectory.getLogger();

	@Override
	public void setup(final TriggerSetupContext aContext) {
	}

	@Override
	public final void handleBeforeCreate(final BeforeCreateOccurrenceContext aContext) throws OperationException {
		/*
		 * final Path toPassword = Path.parse("password"); final String
		 * passwordValue = (String)
		 * aContext.getOccurrenceContextForUpdate().getValue(toPassword);
		 * aContext.getOccurrenceContextForUpdate().setValue(DirectoryDefault.
		 * encryptString(passwordValue), toPassword);
		 */
	}

	@Override
	public final void handleAfterCreate(final AfterCreateOccurrenceContext aContext) throws OperationException {
/*		final Path passwordPath = Path.parse("password");
		final String passwordValue = aContext.getAdaptationOccurrence().get(passwordPath)!=null?(String)aContext.getAdaptationOccurrence().get(passwordPath):null;
		System.out.println("passwordValue="+passwordValue);
		if(passwordValue!=null){
			if(!isValidPassword(passwordValue)){
				throw OperationException.createError("Invalid password.\nPassword must :\nblah\nblah\nblah\nblah\n PV:"+passwordValue);
			}
		}*/
	}

	@Override
	public final void handleAfterModify(final AfterModifyOccurrenceContext aContext) throws OperationException {
		LOGGER.fine("UsersTrigger handleAfterModify->");
		final Path passwordPath = Path.parse("password");
		final Path passwordLastUpdatePath = Path.parse("passwordLastUpdate");
		Date currentTime = Date.from(Instant.now());
		ProcedureContext procedureContext = aContext.getProcedureContext();
		ValueContextForUpdate valueContextForUpdate = procedureContext.getContext(aContext.getAdaptationOccurrence().getAdaptationName());
		if(aContext.getChanges().getChange(passwordPath)!=null){
			LOGGER.fine("UsersTrigger password changed");
			valueContextForUpdate.setValue(currentTime, passwordLastUpdatePath);
			procedureContext.doModifyContent(aContext.getAdaptationOccurrence(), valueContextForUpdate);
		}else{
			LOGGER.fine("UsersTrigger password not changed");
		}
		//LOGGER.info("UsersTrigger password="+aContext.getAdaptationOccurrence().get(passwordPath));
	}

	@Override
	public final void handleAfterDelete(final AfterDeleteOccurrenceContext aContext) throws OperationException {
		final String userId = (String) aContext.getOccurrenceContext().getValue(Path.parse("userId"));
		final AdaptationTable userRoleTable = aContext.getTable().getContainerAdaptation().getTable(Path.parse("/root/UserRole"));
		
		final List<Adaptation> records = userRoleTable.selectOccurrences(String.format("userId = '%s'", userId));
		if (records != null) {
			for (final Adaptation userRoleRecord : records) {
				aContext.getProcedureContext().doDelete(userRoleRecord.getAdaptationName(), false);
			}
		}
	}

	private boolean isValidPassword(String password){
		if(password!=null){
			Pattern pattern = Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$");
			Matcher matcher = pattern.matcher(password);
			return matcher.matches();
		}
		return false;
	}
}
