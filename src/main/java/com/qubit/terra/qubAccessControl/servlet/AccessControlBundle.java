package com.qubit.terra.qubAccessControl.servlet;

import java.util.ResourceBundle;
import java.util.regex.Matcher;

import org.apache.commons.lang.LocaleUtils;

public class AccessControlBundle {

	private static final String BUNDLE_NAME = "resources.AccesscontrolResources";
	private static ResourceBundle bundle = ResourceBundle.getBundle(BUNDLE_NAME);

	public static String get(String key) {
		return bundle.getString(key);
	}

	public static String get(String key, String... args) {

		String message = bundle.getString(key);
		for (int i = 0; i < args.length; i++) {
			message = message.replaceAll("\\{" + i + "\\}", args[i] == null ? "" : Matcher.quoteReplacement(args[i]));
		}
		return message;

	}

	public static String localizedString(String key) {

		String keyPT = ResourceBundle.getBundle(BUNDLE_NAME, LocaleUtils.toLocale("pt")).getString(key);

		String keyEN = ResourceBundle.getBundle(BUNDLE_NAME, LocaleUtils.toLocale("en")).getString(key);

		return "{\"pt_PT\":\"" + keyPT + "\",\"en_GB\":\"" + keyEN + "\"}";

	}

}
