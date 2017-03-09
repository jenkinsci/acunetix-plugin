package com.acunetix;

import java.text.MessageFormat;

import static java.util.ResourceBundle.getBundle;

/**
 * Expose message resources
 */
class SR {
    private static java.util.ResourceBundle acunetixBundle = getBundle("Messages");

    private SR() {
    }

    static String getString(String key, Object... args) {
        String message = acunetixBundle.getString(key);

        if (args != null && args.length > 0) {
            return MessageFormat.format(message, args);
        }
        return message;
    }
}
