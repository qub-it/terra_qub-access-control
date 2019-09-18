package com.qubit.terra.qubAccessControl.servlet;

import java.util.ResourceBundle;
import java.util.regex.Matcher;

public class AccessControlBundle {

	private static final String BUNDLE_NAME = "resources.AccesscontrolResources";
	private static ResourceBundle bundle = ResourceBundle.getBundle(BUNDLE_NAME);

	public static String accessControlBundle(String key) {
		return bundle.getString(key);
	}

	public static String accessControlBundle(String key, String... args) {

		String message = bundle.getString(key);
		for (int i = 0; i < args.length; i++) {
			message = message.replaceAll("\\{" + i + "\\}", args[i] == null ? "" : Matcher.quoteReplacement(args[i]));
		}
		return message;

	}

}
