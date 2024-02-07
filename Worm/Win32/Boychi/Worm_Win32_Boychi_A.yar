
rule Worm_Win32_Boychi_A{
	meta:
		description = "Worm:Win32/Boychi.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 22 00 00 01 00 "
		
	strings :
		$a_80_0 = {61 76 67 6e 74 6d 67 72 2e 73 79 73 } //avgntmgr.sys  01 00 
		$a_80_1 = {61 76 67 6e 74 64 64 2e 73 79 73 } //avgntdd.sys  01 00 
		$a_80_2 = {44 65 65 70 46 72 7a 2e 73 79 73 } //DeepFrz.sys  01 00 
		$a_80_3 = {65 65 79 65 68 2e 73 79 73 } //eeyeh.sys  01 00 
		$a_80_4 = {70 72 6f 63 67 75 61 72 64 2e 73 79 73 } //procguard.sys  01 00 
		$a_80_5 = {66 77 64 72 76 2e 73 79 73 } //fwdrv.sys  01 00 
		$a_80_6 = {69 6e 73 70 65 63 74 2e 73 79 73 } //inspect.sys  01 00 
		$a_80_7 = {70 61 76 70 72 6f 63 2e 73 79 73 } //pavproc.sys  01 00 
		$a_80_8 = {74 6d 63 6f 6d 6d 2e 73 79 73 } //tmcomm.sys  01 00 
		$a_80_9 = {76 73 64 61 74 61 6e 74 2e 73 79 73 } //vsdatant.sys  01 00 
		$a_80_10 = {64 72 69 76 65 72 73 76 73 64 61 74 61 6e 74 2e 73 79 73 } //driversvsdatant.sys  01 00 
		$a_80_11 = {41 73 68 41 76 53 63 61 6e 2e 73 79 73 } //AshAvScan.sys  01 00 
		$a_80_12 = {77 70 73 64 72 76 6e 74 2e 73 79 73 } //wpsdrvnt.sys  01 00 
		$a_80_13 = {41 56 47 49 44 53 78 78 2e 73 79 73 } //AVGIDSxx.sys  02 00 
		$a_80_14 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  02 00 
		$a_80_15 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //autorun.inf  02 00 
		$a_80_16 = {61 75 74 6f 72 75 6e 2e 65 78 65 } //autorun.exe  01 00 
		$a_80_17 = {4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 } //Outlook Express  01 00 
		$a_80_18 = {4d 69 63 72 6f 73 6f 66 74 20 4f 75 74 6c 6f 6f 6b } //Microsoft Outlook  01 00 
		$a_80_19 = {53 6f 66 74 77 61 72 65 5c 47 6f 6f 67 6c 65 5c 47 6f 6f 67 6c 65 20 54 61 6c 6b 5c 41 63 63 6f 75 6e 74 73 } //Software\Google\Google Talk\Accounts  01 00 
		$a_80_20 = {50 6c 75 67 69 6e 20 4d 61 6e 61 67 65 72 5c 73 6b 79 70 65 50 4d 2e 65 78 65 } //Plugin Manager\skypePM.exe  01 00 
		$a_80_21 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 53 4e 4d 65 73 73 65 6e 67 65 72 } //Software\Microsoft\MSNMessenger  01 00 
		$a_80_22 = {57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 } //Windows Live Messenger  01 00 
		$a_80_23 = {49 6e 66 65 63 74 } //Infect  01 00 
		$a_80_24 = {4d 6f 62 69 6c 65 } //Mobile  01 00 
		$a_80_25 = {55 53 42 20 44 72 69 76 65 } //USB Drive  01 00 
		$a_80_26 = {56 4d 77 61 72 65 } //VMware  9c ff 
		$a_01_27 = {41 64 76 69 73 6f 72 73 20 41 73 73 69 73 74 61 6e 74 5c 41 64 76 69 73 6f 72 73 41 73 73 69 73 74 61 6e 74 2e 70 64 62 } //9c ff  Advisors Assistant\AdvisorsAssistant.pdb
		$a_01_28 = {43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 4d 00 61 00 72 00 6b 00 65 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 73 00 } //9c ff  Client Marketing Systems
		$a_01_29 = {53 00 74 00 61 00 72 00 20 00 43 00 69 00 74 00 79 00 20 00 4f 00 6e 00 6c 00 69 00 6e 00 65 00 20 00 47 00 61 00 6d 00 65 00 } //9c ff  Star City Online Game
		$a_01_30 = {4c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3d 00 54 00 57 00 26 00 43 00 61 00 74 00 65 00 67 00 6f 00 72 00 79 00 3d 00 4c 00 6f 00 67 00 69 00 6e 00 26 00 52 00 65 00 67 00 69 00 6f 00 6e 00 3d 00 38 00 38 00 36 00 26 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 4e 00 61 00 6d 00 65 00 3d 00 } //9c ff  Language=TW&Category=Login&Region=886&ServiceName=
		$a_01_31 = {50 73 79 63 68 6f 64 61 74 4f 66 66 69 63 65 2e 70 64 62 } //9c ff  PsychodatOffice.pdb
		$a_01_32 = {50 00 73 00 79 00 63 00 68 00 6f 00 44 00 61 00 74 00 20 00 6f 00 66 00 66 00 69 00 63 00 65 00 } //9c ff  PsychoDat office
		$a_01_33 = {41 6e 56 69 72 20 54 61 73 6b 20 4d 61 6e 61 67 65 72 } //00 00  AnVir Task Manager
	condition:
		any of ($a_*)
 
}