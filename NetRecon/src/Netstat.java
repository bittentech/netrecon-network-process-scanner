import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import com.maxmind.geoip2.DatabaseReader;
import io.ipinfo.api.IPInfo;
import io.ipinfo.api.cache.SimpleCache;
import io.ipinfo.api.errors.RateLimitedException;
import io.ipinfo.api.model.IPResponse;

import javax.annotation.processing.SupportedSourceVersion;
import java.io.*;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Netstat {

    public static void scanFile(String filepath) {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("YOUR_VIRUSTOTAL_API_KEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();


            System.out.println("File path: "+filepath);

            System.out.println("Uploading file to VirusTotal..");

            ScanInfo scanInformation = virusTotalRef.scanFile(new File(filepath));

            System.out.println("Scanning file with VirusTotal..");

            System.out.println("___SCAN INFORMATION___");
            System.out.println("MD5 :\t" + scanInformation.getMd5());
            System.out.println("Perma Link :\t" + scanInformation.getPermalink());
            System.out.println("Resource :\t" + scanInformation.getResource());
            System.out.println("Scan Date :\t" + scanInformation.getScanDate());
            System.out.println("Scan Id :\t" + scanInformation.getScanId());
            System.out.println("SHA1 :\t" + scanInformation.getSha1());
            System.out.println("SHA256 :\t" + scanInformation.getSha256());
            System.out.println("Verbose Msg :\t" + scanInformation.getVerboseMessage());
            System.out.println("Response Code :\t" + scanInformation.getResponseCode());
            System.out.println("done.");
            System.out.println("Getting Scan Report..");
            getFileScanReport(scanInformation.getResource());
        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }


    }

    public static void getFileScanReport(String resource) {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("YOUR_VIRUSTOTAL_API_KEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            //String resource="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
            FileScanReport report = virusTotalRef.getScanReport(resource);

            System.out.println("MD5 :\t" + report.getMd5());
            System.out.println("Perma link :\t" + report.getPermalink());
            System.out.println("Resource :\t" + report.getResource());
            System.out.println("Scan Date :\t" + report.getScanDate());
            System.out.println("Scan Id :\t" + report.getScanId());
            System.out.println("SHA1 :\t" + report.getSha1());
            System.out.println("SHA256 :\t" + report.getSha256());
            System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
            System.out.println("Response Code :\t" + report.getResponseCode());
            System.out.println("Positives :\t" + report.getPositives());
            System.out.println("Total :\t" + report.getTotal());

            Map<String, VirusScanInfo> scans = report.getScans();
            for (String key : scans.keySet()) {
                VirusScanInfo virusInfo = scans.get(key);
                System.out.println("Scanner : " + key);
                System.out.println("\t\t Result : " + virusInfo.getResult());
                System.out.println("\t\t Update : " + virusInfo.getUpdate());
                System.out.println("\t\t Version :" + virusInfo.getVersion());
            }

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }



    public static void  main(String args[])
    {

        IPInfo ipInfo = IPInfo.builder().setToken("YOUR_IPINFO_TOKEN").setCache(new SimpleCache(Duration.ofDays(5))).build();



        String remote_addr=null;
        final String cmd = "netstat -ao -n -p TCP";
        ArrayList<String> pids=new ArrayList<>();



        try {

            String command="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe get-process | Select ID,Name,Path | format-table –AutoSize";

            //runPowershell(command);


            InetAddress address = InetAddress.getByName("YOUR_PC_NAME");
            System.out.println(address.getHostAddress());

            Process process = Runtime.getRuntime().exec(cmd);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            Integer a=9;
            Integer b,c;
            while ((line = reader.readLine()) != null) {
// Parse line for required info
                if(line.length()>=20 && !line.contains("Local") && !line.contains("0.0.0.0") && !line.contains("127.0.0.1")) {
                    System.out.println();
                    a=9;
                    while(line.charAt(a)!=' ') a++;
                    //System.out.println("a= "+a);
                    System.out.println("Local Address:"+line.substring(9, a));
                    a=a++;
                    while(line.charAt(a)==' ') a++;
                    b=a;
                    while(line.charAt(b)!=' ') b++;

                    remote_addr=line.substring(a, b);
                    System.out.println("Remote Address:"+line.substring(a, b));


                    //Geolocation
                    System.out.println("Locating Remote IP "+remote_addr.substring(0,remote_addr.indexOf(':'))+" ..");




                    if(!remote_addr.substring(0,remote_addr.indexOf(':')).contains("0.0.0.0")) {
                        try {
                            IPResponse response = ipInfo.lookupIP(remote_addr.substring(0,remote_addr.indexOf(':')).trim());

                            // Print out the hostname
                            System.out.println("Hostname: " + response.getHostname());

                            System.out.println("Latitude: " + response.getLatitude());
                            System.out.println("Longitude: " + response.getLongitude());
                            System.out.println("Country: " + response.getCountryName());
                            System.out.println("City: " + response.getCity());
                            System.out.println("Company: " + response.getCompany());
                            System.out.println("Region: " + response.getRegion());

                        } catch (Exception ex) {
                            // Handle rate limits here.
                            System.out.println("Exception: " + ex.getMessage());
                        }
                    }



                    b++;
                    while(line.charAt(b)==' ') b++;
                    c=b;
                    while(line.charAt(c)!=' ') c++;
                    System.out.println("Status:"+line.substring(b, c));

                    c++;
                    while(line.charAt(c)==' ') c++;

                    //while(line.charAt(d)!=' ') d++;
                    pids.add(line.substring(c, line.length()));
                    System.out.println("Process ID:"+line.substring(c, line.length()));
                }

            }



            //scanFile();
            Scanner p=new Scanner(System.in);
            System.out.print("Enter process ID to search:");
            String id=p.next();

            final String cmd1 = "tasklist.exe /v /fi \"PID eq "+id+"\"";
            Process process_task = Runtime.getRuntime().exec(cmd1);

            BufferedReader reader_task = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            System.out.println("Task name for pid "+id+":");


            String filename = null;

            String filepath=getFilePathFromId(id);
            Integer taskname_cnt=0;
            reader_task = new BufferedReader(
                    new InputStreamReader(process_task.getInputStream()));
            //System.out.println("Refined outputs:");

            while ((line = reader_task.readLine()) != null) {
// Parse line for required info

                if(line.length()!=0 && !line.contains("Image") && !line.contains("==")) {
                    while (line.charAt(taskname_cnt) != ' ') taskname_cnt++;
                    filename=line.substring(0, taskname_cnt);
                    System.out.println(line.substring(0, taskname_cnt));
                }

            }
            reader.close();







            scanFile(filepath);


            /*InputStream in = process.getInputStream();

            File tmp = File.createTempFile("allConnections","txt");

            byte[] buf = new byte[256];

            OutputStream outputConnectionsToFile = new OutputStream() {
                @Override
                public void write(int b)  {
                    System.out.print((char)b);
                }
            };

            int numbytes = 0;

            while ((numbytes = in.read(buf, 0, 256)) != -1) {

                outputConnectionsToFile.write(buf, 0, numbytes);

            }

            System.out.println("File is present at "+tmp.getAbsolutePath());

            */
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

    public static void runPowershell(String command) throws IOException {
        //String command = "powershell.exe  your command";
        //Getting the version

        // Executing the command
        Process powerShellProcess = Runtime.getRuntime().exec(command);
        // Getting the results
        powerShellProcess.getOutputStream().close();
        String line;
        System.out.println("Standard Output:");
        BufferedReader stdout = new BufferedReader(new InputStreamReader(
                powerShellProcess.getInputStream()));
        while ((line = stdout.readLine()) != null) {
            System.out.println(line);
        }
        stdout.close();
        System.out.println("Standard Error:");
        BufferedReader stderr = new BufferedReader(new InputStreamReader(
                powerShellProcess.getErrorStream()));
        while ((line = stderr.readLine()) != null) {
            System.out.println(line);
        }
        stderr.close();
        System.out.println("Done");
    }

    public static String getFilePathFromId(String id) throws IOException
    {
        String command="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe get-process -Id "+id+" | Select Path";

        String path=null;
        //String command = "powershell.exe  your command";
        //Getting the version

        // Executing the command
        Process powerShellProcess = Runtime.getRuntime().exec(command);
        // Getting the results
        powerShellProcess.getOutputStream().close();
        String line;
        System.out.println("Standard Output:");
        BufferedReader stdout = new BufferedReader(new InputStreamReader(
                powerShellProcess.getInputStream()));
        while ((line = stdout.readLine()) != null) {

                System.out.println(line);
                if(!line.contains("Path") && !line.contains("---") && line.trim().length()!=0)
                {
                    path=line.trim();
                    System.out.println("Path from powershell: "+path);

                }

        }
        stdout.close();
        System.out.println("Standard Error:");
        BufferedReader stderr = new BufferedReader(new InputStreamReader(
                powerShellProcess.getErrorStream()));
        while ((line = stderr.readLine()) != null) {
            System.out.println(line);
        }
        stderr.close();
        System.out.println("Done");

        return path;

    }





}
