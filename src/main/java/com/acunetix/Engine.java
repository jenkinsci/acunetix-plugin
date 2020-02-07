package com.acunetix;

import net.sf.json.JSONArray;
import net.sf.json.JSONNull;
import net.sf.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;


public class Engine {
    private String apiUrl;
    private String apiKey;
    private static final Map<String, String[]> threatCategory = new HashMap<>();

    static {
        threatCategory.put("High", new String[]{"3"});
        threatCategory.put("Medium", new String[]{"3", "2"});
        threatCategory.put("Low", new String[]{"3", "2", "1"});
    }

    public Engine(String apiUrl, String apiKey) {
//        System.setProperty("proxySet", "true");
//        System.getProperty("proxySet");

        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
    }

    public static String getThreatName(String threat) {
        switch (threat) {
            case "3":
                return "High";
            case "2":
                return "Medium";
            case "1":
                return "Low";
        }
        return null;
    }

    private static class Resp {
        int respCode;
        String respStr = null;
        JSONObject jso = null;
    }

    private HttpsURLConnection openConnection(String endpoint, String method) throws IOException {
        return openConnection(endpoint, method, "application/json; charset=UTF-8");
    }

    private HttpsURLConnection openConnection(String endpoint) throws IOException {
        return openConnection(endpoint, "GET", "application/json; charset=UTF-8");
    }

    private HttpsURLConnection openConnection(String endpoint, String method, String contentType) throws IOException {
        URL url = new URL(endpoint);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        connection.setRequestProperty("Content-Type", contentType);
        connection.setRequestProperty("User-Agent", "Mozilla/5.0");
        connection.addRequestProperty("X-AUTH", apiKey);
        return connection;
    }

    private Resp doGet(String urlStr) throws IOException {
        HttpsURLConnection connection = openConnection(urlStr);
        try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"))) {
            String inputLine;
            StringBuilder resbuf = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                resbuf.append(inputLine);
            }
            Resp resp = new Resp();
            resp.respCode = connection.getResponseCode();
            resp.jso = JSONObject.fromObject(resbuf.toString());
            return resp;
        }
    }

    public String getUrl(String apiUrl, String downloadLink) throws MalformedURLException {
        URL url = new URL(apiUrl);
        if (downloadLink.matches("^(http|https)://.*$")) {
            return downloadLink;
        } else {
            return url.getProtocol() + "://" + url.getAuthority() + downloadLink;
        }
    }

    public int doTestConnection(String urlStr) throws IOException {
        HttpsURLConnection connection = openConnection(urlStr);
        return connection.getResponseCode();
    }

    private Resp doPost(String urlStr) throws IOException {
        HttpsURLConnection connection = openConnection(urlStr,"POST");
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        Resp resp = new Resp();
        resp.respCode = connection.getResponseCode();
        return resp;
    }

    private Resp doDelete(String urlStr) throws IOException {
        HttpsURLConnection connection = openConnection(urlStr,"DELETE");
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        Resp resp = new Resp();
        resp.respCode = connection.getResponseCode();
        return resp;
    }

    private Resp doPostLoc(String urlStr, String urlParams) throws IOException, NullPointerException {
        HttpsURLConnection connection = openConnection(urlStr, "POST");
        connection.setUseCaches(false);
        connection.setDoInput(true);
        connection.setDoOutput(true);

        try (DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream())) {
            outputStream.writeBytes(urlParams);
        }
        String location = connection.getHeaderField("Location");
        Resp resp = new Resp();
        resp.respCode = connection.getResponseCode();
        try {
            resp.respStr = location.substring(location.lastIndexOf("/") + 1);
            } catch (NullPointerException e){
            e.printStackTrace();
                    throw new ConnectionException();
            }
        return resp;
    }

    private JSONArray getObjects(String objectName) throws IOException, NullPointerException {
        JSONArray objects = null;
        JSONArray cursors;

        Resp resp = doGet(apiUrl + "/" + objectName);
        if (resp.respCode != 200) {
                throw new IOException(SR.getString("bad.response.0", resp.respCode));
            }
            objects = resp.jso.getJSONArray(objectName);
            JSONObject pagination = resp.jso.getJSONObject("pagination");
            if (pagination.containsKey("next_cursor")) {
                Integer cursor = 0;
                while ((cursor >= 100) || (cursor%100>0)) {
                    resp = doGet(apiUrl + "/" + objectName + "?c=" + cursor);
                    objects.addAll(resp.jso.getJSONArray(objectName));
                    pagination = resp.jso.getJSONObject("pagination");
                    if (pagination.getString("next_cursor").equals("null")) {
                        break;
                    }
                    cursor = pagination.getInt("next_cursor");
                }
            }
            else{
                if (pagination.size() > 0) {
                    cursors = pagination.getJSONArray("cursors");
                    String cursor;
                    while (cursors.size() > 2) {
                        cursors = pagination.getJSONArray("cursors");
                        cursor = cursors.getString(1);
                        resp = doGet(apiUrl + "/" + objectName + "?c=" + cursor);
                        objects.addAll(resp.jso.getJSONArray(objectName));
                        pagination = resp.jso.getJSONObject("pagination");
                    }
                }
            }

//        }
        return objects;
    }

    public JSONArray getTargets() throws IOException {
        return getObjects("targets");
    }


    public String getTargetName(String targetId) throws IOException {
        JSONArray targets = getTargets();
        for (int i = 0; i < targets.size(); i++) {
            JSONObject item = targets.getJSONObject(i);
            String target_id = item.getString("target_id");
            if (target_id.equals(targetId)) {
                String address = item.getString("address");
                String description = item.getString("description");
                String target_name = address;
                if (description.length() > 0) {
                    if (description.length() > 100) {
                        description = description.substring(0, 100);
                    }
                    target_name += "  (" + description + ")";
                }
                return target_name;
            }
        }
        return null;
    }

    public JSONArray getScanningProfiles() throws IOException {
        return getObjects("scanning_profiles");
    }

    public Boolean checkScanProfileExists(String profileId) throws IOException {
        JSONArray profiles = getScanningProfiles();
        for (int i = 0; i < profiles.size(); i++) {
            JSONObject item = profiles.getJSONObject(i);
            String profile_id = item.getString("profile_id");
            if (profile_id.equals(profileId)) {
                return true;
            }
        }
        return false;
    }

    public Boolean checkScanExist(String scanId) {
        try {
            JSONArray scans = getScans();
            for (int i = 0; i < scans.size(); i++) {
                JSONObject item = scans.getJSONObject(i);
                String id = item.getString("scan_id");
                if (id.equals(scanId)) {
                    return true;
                }
            }
        }
        catch (IOException e){
            e.printStackTrace();
        }
        return false;
    }

    public String startScan(String scanningProfileId, String targetId, Boolean waitFinish) throws IOException {
        JSONObject jso = new JSONObject();
        jso.put("target_id", targetId);
        jso.put("profile_id", scanningProfileId);
        jso.put("user_authorized_to_scan", "yes");
        JSONObject jsoChild = new JSONObject();
        jsoChild.put("disable", false);
        jsoChild.put("start_date", JSONNull.getInstance());
        jsoChild.put("time_sensitive", false);
        jso.put("schedule", jsoChild);
        String scanId = doPostLoc(apiUrl + "/scans", jso.toString()).respStr;
        if (waitFinish) {
            while (!getScanStatus(scanId).equals("completed")) {
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
        return scanId;
    }

    public String createIncScan(String scanningProfileId, String targetId) throws IOException {
        JSONObject jso = new JSONObject();
        jso.put("target_id", targetId);
        jso.put("profile_id", scanningProfileId);
        jso.put("user_authorized_to_scan", "yes");
        jso.put("incremental", true);
        JSONObject jsoChild = new JSONObject();
        jsoChild.put("disable", false);
        jsoChild.put("start_date", JSONNull.getInstance());
        jsoChild.put("time_sensitive", false);
        jsoChild.put("triggerable", true);
        jso.put("schedule", jsoChild);
        String scanId = doPostLoc(apiUrl + "/scans", jso.toString()).respStr;
        return scanId;
    }

    public String triggerIncScan(String scanId, Boolean waitFinish) throws IOException {
        String resScanId = doPost(apiUrl + "/scans/" + scanId + "/trigger").respStr;
        if (waitFinish) {
            while (!getScanStatus(scanId).equals("completed")) {
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
        return resScanId;
    }

    public JSONArray getScans() throws IOException {
        return getObjects("scans");
    }

    public String getScanThreat(String scanId) throws IOException {
        JSONObject jso = doGet(apiUrl + "/scans/" + scanId).jso;
        return jso.getJSONObject("current_session").getString("threat");
    }

    public String getScanStatus(String scanId) throws IOException {
        JSONObject jso = doGet(apiUrl + "/scans/" + scanId).jso;
        return jso.getJSONObject("current_session").getString("status");
    }

    public String getScanProfile(String scanId) throws IOException {
        JSONObject jso = doGet(apiUrl + "/scans/" + scanId).jso;
        return jso.getString("profile_id");
    }

    public String getScanTarget(String scanId) throws IOException {
        JSONObject jso = doGet(apiUrl + "/scans/" + scanId).jso;
        return jso.getString("target_id");
    }

    public void stopScan(String scanId) {
        try {
            Resp resp = doPost(apiUrl + "/scans/" + scanId + "/abort");
            if (resp.respCode != 204) {
                throw new IOException(SR.getString("bad.response.0", resp.respCode));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void deleteScan(String scanId) {
        try {
            doDelete(apiUrl + "/scans/" + scanId);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public JSONArray getReportTemplates() throws IOException {
        Resp resp = doGet(apiUrl + "/report_templates");
        if (resp.respCode == 200) {
            return resp.jso.getJSONArray("templates");
        }
        throw new IOException(SR.getString("bad.response.0", resp.respCode));
    }

    public String getReportTemplateName(String reportTemplateId) throws IOException {
        JSONArray jsa = getReportTemplates();
        for (int i = 0; i < jsa.size(); i++) {
            JSONObject item = jsa.getJSONObject(i);
            if (item.getString("template_id").equals(reportTemplateId)) {
                return item.getString("name");
            }
        }
        return null;
    }

    private String getReportStatus(String reportId) throws IOException {
        JSONObject jso = doGet(apiUrl + "/reports/" + reportId).jso;
        return jso.getString("status");
    }

    public void waitReportStatus(String reportId) throws IOException, InterruptedException {
        while (!getReportStatus(reportId).equals("completed")) {
            Thread.sleep(10000);
        }
    }

    public String generateReport(String sourceId, String reportTemplateId, String listType) throws IOException, InterruptedException {
        //returns download link of html report
        JSONObject jso = new JSONObject();
        jso.put("template_id", reportTemplateId);
        JSONObject jsoChild = new JSONObject();
        jsoChild.put("list_type", listType);
        List<String> id_list = new ArrayList<>();
        id_list.add(sourceId);
        jsoChild.put("id_list", id_list);
        jso.put("source", jsoChild);
        String reportId = doPostLoc(apiUrl + "/reports", jso.toString()).respStr;
        waitReportStatus(reportId);
        String[] downloadLinkList = doGet(apiUrl + "/reports/" + reportId).jso.getString("download").split(",");
        String downloadLink = null;
        for (String item : downloadLinkList) {
            if (item.contains(".html")) {
                downloadLink = item.replaceAll("\"", "").replaceAll("\\[", "".replaceAll("]", ""));
                break;
            }
        }
        // download report
        return downloadLink;
    }

    public Boolean checkThreat(String checkThreat, String scanThreat) {
        //return true if the threat detected is equal or greater than threat set
        //checkthreat is the level set in plugin config and scanThreat from the scan result
        if (checkThreat.equals("DoNotFail")) {
            return false;
        }
        return Arrays.asList(threatCategory.get(checkThreat)).contains(scanThreat);
    }

    public Integer getVersion() throws IOException {
        JSONObject jso = doGet(apiUrl + "/info").jso;
        return jso.getInt("major_version");
    }
}

class ConnectionException extends RuntimeException {
    public ConnectionException() {
        super(SR.getString("cannot.connect.to.application"));
    }
    public ConnectionException(String message) {
        super(message);
    }
}
