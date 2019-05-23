package unimelb.bitbox;

import org.kohsuke.args4j.Option;

public class CMDReader {

    @Option(required = true, name = "-c", aliases = {"--command"}, usage = "command")
    private String command;

    @Option(required = true, name = "-s", aliases = {"--server"}, usage = "server")
    private String server;

    @Option(required = false, name = "-p", usage = "Peer")
    private String peer;

    public String getCommand() {

        return command;
    }

    public String getPeer() {
        return peer;
    }

    public String getServer() {

        return server;
    }

}
