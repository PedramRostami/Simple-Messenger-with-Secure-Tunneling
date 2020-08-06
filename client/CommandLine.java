package client;

public class CommandLine {
    public static class TYPE {
        public static final int MESSAGE_COMMAND = 1;
        public static final int FILE_COMMAND = 2;
        public static final int UNDEFINE_COMMAND = 3;
    }
    public static int commandType(String commandLine) {
        try {
            String[] commandParts = commandLine.split(" ");
            if ("message".equalsIgnoreCase(commandParts[1])) {
                return TYPE.MESSAGE_COMMAND;
            } else if ("file".equalsIgnoreCase(commandParts[1])) {
                return TYPE.FILE_COMMAND;
            } else
                return TYPE.UNDEFINE_COMMAND;
        } catch (Exception e) {
            return TYPE.UNDEFINE_COMMAND;
        }
    }

    public static String[] getCommandParts(String commandLine) {
        String[] commandLineParts = commandLine.split(" ");
        String[] commandParts = new String[2];
        commandParts[0] = commandLineParts[0];
        commandParts[1] = commandLine.substring(commandLineParts[0].length() + commandLineParts[1].length() + 2);
        return commandParts;
    }


}
