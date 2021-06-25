package com.acunetix;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.POST;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLHandshakeException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;

import static com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials;


public class BuildScanner extends hudson.tasks.Builder implements SimpleBuildStep {
    private final String profile;
    private final String target;
    private String targetName;
    private final String repTemp;
    private String reportTemplateName;
    private final String threat;
    private final Boolean stopScan;
    private Boolean incScan;
    private String incScanId;
    private final Boolean svRep;
    private final Boolean stopTargetScans;


    @DataBoundConstructor
    public BuildScanner(String profile, String target, String repTemp, String threat, Boolean stopScan, Boolean svRep, Boolean incScan, String incScanId, Boolean stopTargetScans) {
        this.profile = profile;
        this.target = target;
        this.repTemp = repTemp;
        this.threat = threat;
        this.stopScan = stopScan;
        this.svRep = svRep;
        this.stopTargetScans = stopTargetScans;
        this.incScan = incScan;
        try {
            Engine aac = new Engine(getDescriptor().getgApiUrl(), getDescriptor().getgApiKey());
            if (aac.getVersion() > 12) {
                if (incScan) {
                    if (aac.checkIncScanExist(target, profile)) {
                        this.incScanId = aac.getIncScanId(target,profile);
                    }
                    else {
                        this.incScanId = aac.createIncScan(profile, target);
                    }
                }
                else{
                    this.incScanId = incScanId;
                }
            }
            else {
                this.incScan = false;
            }
            this.targetName = aac.getTargetName(this.target);
            this.reportTemplateName = aac.getReportTemplateName(this.repTemp);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public String getProfile() {
        return profile;
    }


    public String getTarget() {
        return target;
    }

    public String getRepTemp() {
        return repTemp;
    }

    public String getThreat() {
        return threat;
    }

    public Boolean getStopScan() {
        return stopScan;
    }

    private String getTargetName() {
        return targetName;
    }

    private String getReportTemplateName() {
        return reportTemplateName;
    }

    public Boolean getIncScan() {
        return incScan;
    }

    public String getIncScanId() {
        return incScanId;
    }

    public Boolean getStopTargetScans() {
        return stopTargetScans;
    }

    public Boolean getSvRep() { return svRep; }

    @Override
    public void perform(@Nonnull Run<?, ?> build, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener) throws hudson.AbortException, InterruptedException {
        final String PROCESSING = "processing";
        final String COMPLETED = "completed";
        final String ABORTED = "aborted";
        final String SCHEDULED = "scheduled";
        final String QUEUED = "queued";
        final String NOREPORT = "no_report";
        final String FAILED = "failed";
        final PrintStream listenerLogger = listener.getLogger();

        Engine engine = new Engine(getDescriptor().getgApiUrl(), getDescriptor().getgApiKey());
        String scanId = null;
        Boolean scanAbortedExternally = false;
        Boolean scanAbortedByUser = false;
        String scanStatus = "";
        String scanThreat;
        Boolean started = false;
        Boolean bThreat = false;
        Boolean bScheduled = false;

        try {
            Engine testengine = new Engine(getDescriptor().getgApiUrl(), getDescriptor().getgApiKey());
            int rc = testengine.doTestConnection(getDescriptor().getgApiUrl() + "/me");
            if (rc != 200) {
                listenerLogger.println(SR.getString("aborting.the.build"));
                throw new hudson.AbortException(SR.getString("cannot.connect.to.application"));
                }
            if ((engine.getTargetName(target) == null)) {
                listenerLogger.println(SR.getString("aborting.the.build"));
                throw new hudson.AbortException(SR.getString("invalid.target"));
                }
            else if (!engine.checkScanProfileExists(profile)) {
                listenerLogger.println(SR.getString("aborting.the.build"));
                throw new hudson.AbortException(SR.getString("invalid.scan_type"));
                }
            listenerLogger.println(SR.getString("starting.scan.on.target.0", getTargetName()));
            if (this.stopTargetScans)
            {
                engine.stopTargetScans(target);
            }
            if (this.incScan) {
                if (!engine.checkScanExist(incScanId)) {
                    throw new hudson.AbortException(SR.getString("could.not.find.scan.with.scanid.0.create.new", this.incScanId));
                }
                engine.triggerIncScan(this.incScanId, false);
                scanId = this.incScanId;
            }
            else {
                scanId = engine.startScan(profile, target, false);
                if (scanId == null) {
                    listenerLogger.println(SR.getString("aborting.the.build"));
                    throw new hudson.AbortException(SR.getString("cannot.connect.to.application"));
                }
            }
            while (!scanStatus.equals(COMPLETED)) {
                if (scanStatus.equals(PROCESSING) && !started) {
                    started = true;
                    listenerLogger.println(SR.getString("scan.started"));
                    listenerLogger.println(SR.getString("view.scan.status") + getDescriptor().getgApiUrl().replace("api/v1", "#") + "/scans/" + scanId + "/info");
                }
                if (scanStatus.equals(SCHEDULED) && !bScheduled) {
                    bScheduled = true;
                    listenerLogger.println(SR.getString("the.scan.is.in.scheduled.state"));
                }
                if (scanStatus.equals(ABORTED)) {
                    scanAbortedExternally = true;
                    listenerLogger.println(SR.getString("aborting.the.build"));
                    throw new hudson.AbortException(SR.getString("scan.aborted.outside"));
                }

                if (scanStatus.equals(FAILED)) {
                    scanAbortedExternally = true;
                    listenerLogger.println(SR.getString("scan.failed"));
                    throw new hudson.AbortException(SR.getString("scan.failed"));                    
                }

                scanThreat = engine.getScanThreat(scanId);
                if (engine.checkThreat(threat, scanThreat)) {
                    bThreat = true;
                    //listenerLogger.println(SR.getString("scan.threat.0.1", Engine.getThreatName(scanThreat), this.getThreat()));
                    listenerLogger.println(SR.getString("scan.threat.0", Engine.getThreatName(scanThreat)));
                    listenerLogger.println(SR.getString("check.vulnerabilities.found") + getDescriptor().getgApiUrl().replace("api/v1", "#") + "/scans/" + scanId + "/vulnerabilities");
                    listenerLogger.println(SR.getString("aborting.the.build"));
                    throw new hudson.AbortException(SR.getString("scan.threat"));
                }
                Thread.sleep(10000);
                scanStatus = engine.getScanStatus(scanId);
            }
            listenerLogger.println(SR.getString("scan.completed"));
        } catch (InterruptedException e) {
            scanAbortedByUser = true;
            listenerLogger.println(SR.getString("aborting.the.build"));
            throw new hudson.AbortException(SR.getString("build.aborted"));
        } catch (hudson.AbortException e) {
            throw e;
        } catch (SSLHandshakeException e) {
            e.printStackTrace();
            throw new hudson.AbortException(SR.getString("certificate.to.the.java.ca.store"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            if (!engine.checkScanExist(scanId)) {
                listenerLogger.println(SR.getString("aborting.the.build"));
                scanAbortedExternally = true;
                throw new hudson.AbortException(SR.getString("could.not.find.scan.with.scanid.0", scanId));
            }
        } catch (java.net.ConnectException e) {
            e.printStackTrace();
            listenerLogger.println(SR.getString("aborting.the.build"));
            scanAbortedExternally = true;
            throw new hudson.AbortException(SR.getString("could.not.connect.to.application.connection.refused"));
            } catch (ConnectionException e) {
            listenerLogger.println(SR.getString("aborting.the.build"));
            throw new hudson.AbortException(SR.getString("cannot.connect.to.application"));
        } catch (Exception e) {
            e.printStackTrace();
            listenerLogger.println(e.getMessage());
        } finally {
            try {
                if (stopScan && scanId != null && !scanAbortedExternally && (bThreat || scanAbortedByUser) && !bScheduled) {
                    engine.stopScan(scanId);
                    try {
                        String status = "";
                        while (!status.equals(ABORTED) && !status.equals(COMPLETED)) {
                            Thread.sleep(10000);
                            status = engine.getScanStatus(scanId);
                        }
                        listenerLogger.println(SR.getString("the.scan.was.stopped"));
                    } catch (InterruptedException | IOException e) {
                        e.printStackTrace();
                        listenerLogger.println(e.getMessage());
                    }
                }
                if (!repTemp.equals(NOREPORT) && scanId != null && !scanAbortedByUser && !scanAbortedExternally) {
                    listenerLogger.println(SR.getString("generating.0.report", getReportTemplateName()));
                    Thread.sleep(10000);
                    String downloadLink = engine.generateReport(scanId, repTemp, "scans");
                    listenerLogger.println(SR.getString("scan.report.download.link.0", engine.getUrl(getDescriptor().getgApiUrl(), downloadLink)));
                    if (svRep) {
                        VirtualChannel channel = workspace.getChannel();
                        String reportName = engine.getReportFileName(engine.getUrl(getDescriptor().getgApiUrl(), downloadLink));
                        FilePath reportFile = new hudson.FilePath(channel, workspace.getRemote() + "/" + reportName);
                        engine.doDownload(engine.getUrl(getDescriptor().getgApiUrl(), downloadLink), reportFile);
                        if (reportFile.exists()) {
                            String savedReportUrl = Jenkins.getInstance().getRootUrl() + build.getParent().getUrl() + "ws/" + reportName;
                            listenerLogger.println(SR.getString("report.saved.in.workspace.0", reportName));
                        } else {
                            listenerLogger.println(SR.getString("invalid.report.file.path.0", reportName));
                        }
                    }
                }
            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
                listenerLogger.println(e.getMessage());
            }
        }
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<hudson.tasks.Builder> {
        private String gApiUrl;
        private String gApiKeyID;

        public DescriptorImpl() {
            load();
        }
        @POST
        public FormValidation doTestConnection(@QueryParameter("gApiUrl") final String ApiUrl,
                                               @QueryParameter("gApiKey") final String apiKey) {
            Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
            try {
                if (ApiUrl.length() == 0)
                    return FormValidation.error(SR.getString("please.set.the.api.url"));
                if (!ApiUrl.contains("/api/v1"))
                    return FormValidation.error(SR.getString("invalid.api.url"));
                Engine apio = new Engine(ApiUrl, getgApiKey());
                int respCode = apio.doTestConnection(ApiUrl + "/me");
                if (respCode == 200) {
                    return FormValidation.ok(SR.getString("connected.successfully"));
                }
            } catch (SSLHandshakeException e) {
                e.printStackTrace();
                return FormValidation.error(SR.getString("certificate.to.the.java.ca.store"));
            } catch (IOException e) {
                e.printStackTrace();
                return FormValidation.error(e.getMessage());
            }
            return FormValidation.error(SR.getString("cannot.connect.to.application"));
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Acunetix";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            gApiUrl = formData.getString("gApiUrl");
            gApiKeyID = formData.getString("gApiKeyID");
            save();
            return super.configure(req, formData);
        }

        public String getgApiUrl() {
            return gApiUrl;
        }

        private String getgApiKeyID() {return gApiKeyID;}

        private String getgApiKey() {
            StandardCredentials credentials = null;
            try {
                credentials = CredentialsMatchers.firstOrNull(
                        lookupCredentials(StandardCredentials.class, (Item) null, ACL.SYSTEM, new ArrayList<DomainRequirement>()),
                        CredentialsMatchers.withId(gApiKeyID));
            }
            catch (NullPointerException e) {
                throw new ConnectionException(SR.getString("api.key.not.set"));
            }
            if (credentials != null) {
                if (credentials instanceof StringCredentials) {
                    return ((StringCredentials) credentials).getSecret().getPlainText();
                }
            }
            throw new IllegalStateException("Could not find Acunetix API Key ID: " + gApiKeyID);
        }



        public ListBoxModel doFillProfileItems() throws IOException {
            ListBoxModel items = new ListBoxModel();
            Engine apio = new Engine(gApiUrl, getgApiKey());
            JSONArray jsa = apio.getScanningProfiles();
            for (int i = 0; i < jsa.size(); i++) {
                JSONObject item = jsa.getJSONObject(i);
                String profile_name = item.getString("name");
                String profile_id = item.getString("profile_id");
                items.add(profile_name, profile_id);
            }
            return items;
        }

        public ListBoxModel doFillTargetItems() throws IOException {
            ListBoxModel items = new ListBoxModel();
            Engine apio = new Engine(gApiUrl, getgApiKey());
            JSONArray jsa = apio.getTargets();
            for (int i = 0; i < jsa.size(); i++) {
                JSONObject item = jsa.getJSONObject(i);
                String mi = item.getString("manual_intervention");
                if (mi.equals("null") || mi.equals("false")) {
                    String address = item.getString("address");
                    String target_id = item.getString("target_id");
                    String description = item.getString("description");
                    String target_name = address;
                    if (description.length() > 0) {
                        if (description.length() > 100) {
                            description = description.substring(0, 100);
                        }
                        target_name += "  (" + description + ")";
                    }
                    items.add(target_name, target_id);
                }
            }
            return items;
        }

        public ListBoxModel doFillRepTempItems() throws IOException {
            ListBoxModel items = new ListBoxModel();
            Engine apio = new Engine(gApiUrl, getgApiKey());
            JSONArray jsa = apio.getReportTemplates();
            items.add("Do not generate a report", "no_report");
            for (int i = 0; i < jsa.size(); i++) {
                JSONObject item = jsa.getJSONObject(i);
                String group = item.getString("group");
                String reportTemplate_name = item.getString("name");
                String template_id = item.getString("template_id");
                if (!reportTemplate_name.equals("Scan Comparison")) {
                    items.add(reportTemplate_name, template_id);
                    }
            }
            return items;
        }

        public ListBoxModel doFillThreatItems() throws IOException {
            ListBoxModel items = new ListBoxModel();
            items.add("Do not fail the build", "DoNotFail");
            items.add("High", "High");
            items.add("Medium or High", "Medium");
            items.add("Low, Medium or High", "Low");
            return items;
        }

        public ListBoxModel doFillGApiKeyIDItems(
                @AncestorInPath Item item) {
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(gApiKeyID);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(gApiKeyID);
                }
            }
            if (gApiKeyID != null) {
                result.includeMatchingAs(ACL.SYSTEM, Jenkins.getInstance(), StringCredentials.class,
                        Collections.<DomainRequirement> emptyList(), CredentialsMatchers.allOf(CredentialsMatchers.withId(gApiKeyID)));
            }
            return result
                    .includeMatchingAs(ACL.SYSTEM, Jenkins.getInstance(), StringCredentials.class,
                            Collections.<DomainRequirement> emptyList(), CredentialsMatchers.allOf(CredentialsMatchers.instanceOf(StringCredentials.class)));
        }

        public Boolean testVersion() {
            Boolean res = false;
            try {
                Engine aac = new Engine(getgApiUrl(), getgApiKey());
                res = aac.getVersion() > 12;
            } catch (IOException e) {
                e.printStackTrace();
            }
            return res;
        }
    }
}

