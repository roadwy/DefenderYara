
rule VirTool_WinNT_Higlieder_gen_A{
	meta:
		description = "VirTool:WinNT/Higlieder.gen!A,SIGNATURE_TYPE_PEHSTR,50 00 46 00 57 00 00 "
		
	strings :
		$a_01_0 = {72 65 6c 69 7a 5c 64 72 69 76 65 72 5f 72 6f 6f 74 6b 69 74 5c 64 72 69 76 65 72 5c 6d 5f 68 6f 6f 6b } //1 reliz\driver_rootkit\driver\m_hook
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 6d 00 5f 00 68 00 6f 00 6f 00 6b 00 } //1 \Device\m_hook
		$a_01_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 6d 00 5f 00 68 00 6f 00 6f 00 6b 00 } //1 \DosDevices\m_hook
		$a_01_3 = {66 00 69 00 6c 00 74 00 6e 00 74 00 2e 00 73 00 79 00 73 00 } //1 filtnt.sys
		$a_01_4 = {67 00 75 00 61 00 72 00 64 00 6e 00 74 00 2e 00 73 00 79 00 73 00 } //1 guardnt.sys
		$a_01_5 = {5f 00 41 00 56 00 50 00 4d 00 2e 00 45 00 58 00 45 00 } //1 _AVPM.EXE
		$a_01_6 = {5f 00 41 00 56 00 50 00 43 00 43 00 2e 00 45 00 58 00 45 00 } //1 _AVPCC.EXE
		$a_01_7 = {5f 00 41 00 56 00 50 00 33 00 32 00 2e 00 45 00 58 00 45 00 } //1 _AVP32.EXE
		$a_01_8 = {7a 00 6f 00 6e 00 65 00 61 00 6c 00 61 00 72 00 6d 00 2e 00 65 00 78 00 65 00 } //1 zonealarm.exe
		$a_01_9 = {7a 00 6c 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 zlclient.exe
		$a_01_10 = {5a 00 41 00 55 00 49 00 4e 00 53 00 54 00 2e 00 45 00 58 00 45 00 } //1 ZAUINST.EXE
		$a_01_11 = {7a 00 61 00 74 00 75 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 zatutor.exe
		$a_01_12 = {53 00 59 00 4e 00 4d 00 47 00 52 00 2e 00 45 00 58 00 45 00 } //1 SYNMGR.EXE
		$a_01_13 = {53 00 79 00 6d 00 57 00 53 00 43 00 2e 00 65 00 78 00 65 00 } //1 SymWSC.exe
		$a_01_14 = {53 00 79 00 6d 00 53 00 50 00 6f 00 72 00 74 00 2e 00 65 00 78 00 65 00 } //1 SymSPort.exe
		$a_01_15 = {53 00 79 00 6d 00 50 00 72 00 6f 00 78 00 79 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //1 SymProxySvc.exe
		$a_01_16 = {73 00 79 00 6d 00 6c 00 63 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //1 symlcsvc.exe
		$a_01_17 = {53 00 43 00 41 00 4e 00 33 00 32 00 2e 00 45 00 58 00 45 00 } //1 SCAN32.EXE
		$a_01_18 = {53 00 41 00 56 00 53 00 63 00 61 00 6e 00 2e 00 65 00 78 00 65 00 } //1 SAVScan.exe
		$a_01_19 = {73 00 61 00 76 00 70 00 72 00 6f 00 67 00 72 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 savprogress.exe
		$a_01_20 = {53 00 41 00 56 00 4d 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 SAVMain.exe
		$a_01_21 = {53 00 41 00 56 00 41 00 64 00 6d 00 69 00 6e 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //1 SAVAdminService.exe
		$a_01_22 = {52 00 75 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 } //1 RuLaunch.exe
		$a_01_23 = {52 00 54 00 56 00 53 00 43 00 4e 00 39 00 35 00 2e 00 45 00 58 00 45 00 } //1 RTVSCN95.EXE
		$a_01_24 = {52 00 74 00 76 00 73 00 63 00 61 00 6e 00 2e 00 65 00 78 00 65 00 } //1 Rtvscan.exe
		$a_01_25 = {4e 00 41 00 56 00 57 00 33 00 32 00 2e 00 45 00 58 00 45 00 } //1 NAVW32.EXE
		$a_01_26 = {4e 00 61 00 76 00 4c 00 75 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 NavLu32.exe
		$a_01_27 = {4e 00 41 00 56 00 41 00 50 00 57 00 33 00 32 00 2e 00 45 00 58 00 45 00 } //1 NAVAPW32.EXE
		$a_01_28 = {6e 00 61 00 76 00 61 00 70 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //1 navapsvc.exe
		$a_01_29 = {4b 00 41 00 56 00 53 00 76 00 63 00 55 00 49 00 2e 00 45 00 58 00 45 00 } //1 KAVSvcUI.EXE
		$a_01_30 = {4b 00 41 00 56 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //1 KAVSvc.exe
		$a_01_31 = {4b 00 41 00 56 00 53 00 74 00 61 00 72 00 74 00 2e 00 65 00 78 00 65 00 } //1 KAVStart.exe
		$a_01_32 = {4b 00 61 00 76 00 50 00 46 00 57 00 2e 00 65 00 78 00 65 00 } //1 KavPFW.exe
		$a_01_33 = {4b 00 41 00 56 00 50 00 46 00 2e 00 65 00 78 00 65 00 } //1 KAVPF.exe
		$a_01_34 = {6b 00 61 00 76 00 6d 00 6d 00 2e 00 65 00 78 00 65 00 } //1 kavmm.exe
		$a_01_35 = {4b 00 41 00 56 00 2e 00 65 00 78 00 65 00 } //1 KAV.exe
		$a_01_36 = {49 00 6e 00 6f 00 55 00 70 00 54 00 4e 00 47 00 2e 00 65 00 78 00 65 00 } //1 InoUpTNG.exe
		$a_01_37 = {49 00 6e 00 6f 00 54 00 61 00 73 00 6b 00 2e 00 65 00 78 00 65 00 } //1 InoTask.exe
		$a_01_38 = {49 00 6e 00 6f 00 52 00 54 00 2e 00 65 00 78 00 65 00 } //1 InoRT.exe
		$a_01_39 = {49 00 6e 00 6f 00 52 00 70 00 63 00 2e 00 65 00 78 00 65 00 } //1 InoRpc.exe
		$a_01_40 = {49 00 6e 00 6f 00 63 00 49 00 54 00 2e 00 65 00 78 00 65 00 } //1 InocIT.exe
		$a_01_41 = {49 00 4e 00 45 00 54 00 55 00 50 00 44 00 2e 00 45 00 58 00 45 00 } //1 INETUPD.EXE
		$a_01_42 = {49 00 46 00 41 00 43 00 45 00 2e 00 45 00 58 00 45 00 } //1 IFACE.EXE
		$a_01_43 = {49 00 43 00 53 00 55 00 50 00 50 00 4e 00 54 00 2e 00 45 00 58 00 45 00 } //1 ICSUPPNT.EXE
		$a_01_44 = {49 00 43 00 53 00 55 00 50 00 50 00 39 00 35 00 2e 00 45 00 58 00 45 00 } //1 ICSUPP95.EXE
		$a_01_45 = {49 00 43 00 53 00 53 00 55 00 50 00 50 00 4e 00 54 00 2e 00 45 00 58 00 45 00 } //1 ICSSUPPNT.EXE
		$a_01_46 = {49 00 43 00 4d 00 4f 00 4e 00 2e 00 45 00 58 00 45 00 } //1 ICMON.EXE
		$a_01_47 = {49 00 43 00 4c 00 4f 00 41 00 44 00 4e 00 54 00 2e 00 45 00 58 00 45 00 } //1 ICLOADNT.EXE
		$a_01_48 = {49 00 43 00 4c 00 4f 00 41 00 44 00 39 00 35 00 2e 00 45 00 58 00 45 00 } //1 ICLOAD95.EXE
		$a_01_49 = {47 00 55 00 41 00 52 00 44 00 2e 00 45 00 58 00 45 00 } //1 GUARD.EXE
		$a_01_50 = {47 00 49 00 41 00 4e 00 54 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 GIANTAntiSpywareUpdater.exe
		$a_01_51 = {47 00 49 00 41 00 4e 00 54 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 4d 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 GIANTAntiSpywareMain.exe
		$a_01_52 = {67 00 63 00 61 00 73 00 53 00 65 00 72 00 76 00 2e 00 65 00 78 00 65 00 } //1 gcasServ.exe
		$a_01_53 = {67 00 63 00 61 00 73 00 44 00 74 00 53 00 65 00 72 00 76 00 2e 00 65 00 78 00 65 00 } //1 gcasDtServ.exe
		$a_01_54 = {46 00 2d 00 53 00 74 00 6f 00 70 00 57 00 2e 00 45 00 58 00 45 00 } //1 F-StopW.EXE
		$a_01_55 = {46 00 2d 00 53 00 63 00 68 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 F-Sched.exe
		$a_01_56 = {46 00 2d 00 50 00 52 00 4f 00 54 00 39 00 35 00 2e 00 45 00 58 00 45 00 } //1 F-PROT95.EXE
		$a_01_57 = {46 00 2d 00 41 00 47 00 4e 00 54 00 39 00 35 00 2e 00 45 00 58 00 45 00 } //1 F-AGNT95.EXE
		$a_01_58 = {45 00 7a 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 43 00 68 00 65 00 63 00 6b 00 2e 00 65 00 78 00 65 00 } //1 EzAntivirusRegistrationCheck.exe
		$a_01_59 = {65 00 77 00 69 00 64 00 6f 00 63 00 74 00 72 00 6c 00 2e 00 65 00 78 00 65 00 } //1 ewidoctrl.exe
		$a_01_60 = {45 00 53 00 43 00 41 00 4e 00 48 00 4e 00 54 00 2e 00 45 00 58 00 45 00 } //1 ESCANHNT.EXE
		$a_01_61 = {45 00 53 00 43 00 41 00 4e 00 48 00 39 00 35 00 2e 00 45 00 58 00 45 00 } //1 ESCANH95.EXE
		$a_01_62 = {44 00 52 00 57 00 45 00 42 00 55 00 50 00 57 00 2e 00 45 00 58 00 45 00 } //1 DRWEBUPW.EXE
		$a_01_63 = {64 00 72 00 77 00 65 00 62 00 73 00 63 00 64 00 2e 00 65 00 78 00 65 00 } //1 drwebscd.exe
		$a_01_64 = {64 00 72 00 77 00 65 00 62 00 33 00 32 00 77 00 2e 00 65 00 78 00 65 00 } //1 drweb32w.exe
		$a_01_65 = {64 00 72 00 77 00 61 00 64 00 69 00 6e 00 73 00 2e 00 65 00 78 00 65 00 } //1 drwadins.exe
		$a_01_66 = {44 00 72 00 56 00 69 00 72 00 75 00 73 00 2e 00 65 00 78 00 65 00 } //1 DrVirus.exe
		$a_01_67 = {41 00 56 00 50 00 33 00 32 00 2e 00 45 00 58 00 45 00 } //1 AVP32.EXE
		$a_01_68 = {41 00 56 00 50 00 2e 00 45 00 58 00 45 00 } //1 AVP.EXE
		$a_01_69 = {41 00 56 00 4b 00 57 00 43 00 74 00 6c 00 2e 00 65 00 78 00 65 00 } //1 AVKWCtl.exe
		$a_01_70 = {41 00 56 00 4b 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //1 AVKService.exe
		$a_01_71 = {41 00 76 00 6b 00 53 00 65 00 72 00 76 00 2e 00 65 00 78 00 65 00 } //1 AvkServ.exe
		$a_01_72 = {61 00 76 00 69 00 6e 00 69 00 74 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 avinitnt.exe
		$a_01_73 = {61 00 76 00 67 00 75 00 70 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //1 avgupsvc.exe
		$a_01_74 = {41 00 56 00 47 00 55 00 41 00 52 00 44 00 2e 00 45 00 58 00 45 00 } //1 AVGUARD.EXE
		$a_01_75 = {41 00 56 00 47 00 53 00 45 00 52 00 56 00 2e 00 45 00 58 00 45 00 } //1 AVGSERV.EXE
		$a_01_76 = {41 00 56 00 47 00 4e 00 54 00 2e 00 45 00 58 00 45 00 } //1 AVGNT.EXE
		$a_01_77 = {61 00 76 00 67 00 66 00 77 00 73 00 72 00 76 00 2e 00 65 00 78 00 65 00 } //1 avgfwsrv.exe
		$a_01_78 = {61 00 76 00 67 00 65 00 6d 00 63 00 2e 00 65 00 78 00 65 00 } //1 avgemc.exe
		$a_01_79 = {41 00 56 00 47 00 43 00 54 00 52 00 4c 00 2e 00 45 00 58 00 45 00 } //1 AVGCTRL.EXE
		$a_01_80 = {41 00 56 00 47 00 43 00 43 00 33 00 32 00 2e 00 45 00 58 00 45 00 } //1 AVGCC32.EXE
		$a_01_81 = {61 00 76 00 67 00 63 00 63 00 2e 00 65 00 78 00 65 00 } //1 avgcc.exe
		$a_01_82 = {61 00 76 00 67 00 61 00 6d 00 73 00 76 00 72 00 2e 00 65 00 78 00 65 00 } //1 avgamsvr.exe
		$a_01_83 = {41 00 56 00 45 00 4e 00 47 00 49 00 4e 00 45 00 2e 00 45 00 58 00 45 00 } //1 AVENGINE.EXE
		$a_01_84 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 AntiVirService
		$a_01_85 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 } //1 AntiVirScheduler
		$a_01_86 = {41 00 6e 00 74 00 69 00 2d 00 54 00 72 00 6f 00 6a 00 61 00 6e 00 2e 00 65 00 78 00 65 00 } //1 Anti-Trojan.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1+(#a_01_33  & 1)*1+(#a_01_34  & 1)*1+(#a_01_35  & 1)*1+(#a_01_36  & 1)*1+(#a_01_37  & 1)*1+(#a_01_38  & 1)*1+(#a_01_39  & 1)*1+(#a_01_40  & 1)*1+(#a_01_41  & 1)*1+(#a_01_42  & 1)*1+(#a_01_43  & 1)*1+(#a_01_44  & 1)*1+(#a_01_45  & 1)*1+(#a_01_46  & 1)*1+(#a_01_47  & 1)*1+(#a_01_48  & 1)*1+(#a_01_49  & 1)*1+(#a_01_50  & 1)*1+(#a_01_51  & 1)*1+(#a_01_52  & 1)*1+(#a_01_53  & 1)*1+(#a_01_54  & 1)*1+(#a_01_55  & 1)*1+(#a_01_56  & 1)*1+(#a_01_57  & 1)*1+(#a_01_58  & 1)*1+(#a_01_59  & 1)*1+(#a_01_60  & 1)*1+(#a_01_61  & 1)*1+(#a_01_62  & 1)*1+(#a_01_63  & 1)*1+(#a_01_64  & 1)*1+(#a_01_65  & 1)*1+(#a_01_66  & 1)*1+(#a_01_67  & 1)*1+(#a_01_68  & 1)*1+(#a_01_69  & 1)*1+(#a_01_70  & 1)*1+(#a_01_71  & 1)*1+(#a_01_72  & 1)*1+(#a_01_73  & 1)*1+(#a_01_74  & 1)*1+(#a_01_75  & 1)*1+(#a_01_76  & 1)*1+(#a_01_77  & 1)*1+(#a_01_78  & 1)*1+(#a_01_79  & 1)*1+(#a_01_80  & 1)*1+(#a_01_81  & 1)*1+(#a_01_82  & 1)*1+(#a_01_83  & 1)*1+(#a_01_84  & 1)*1+(#a_01_85  & 1)*1+(#a_01_86  & 1)*1) >=70
 
}