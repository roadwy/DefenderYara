
rule TrojanDownloader_Win32_Renos_gen_T{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!T,SIGNATURE_TYPE_PEHSTR_EXT,ffffffb5 01 ffffffa9 01 15 00 00 "
		
	strings :
		$a_00_0 = {59 6f 75 20 6e 65 65 64 20 74 6f 20 72 65 62 6f 6f 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 74 6f 20 66 69 6e 61 6c 69 7a 65 20 75 6e 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 2e } //100 You need to reboot your computer to finalize uninstallation.
		$a_00_1 = {59 6f 75 20 6e 65 65 64 20 74 6f 20 72 65 62 6f 6f 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 70 72 69 6f 72 20 74 6f 20 75 6e 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 2e } //100 You need to reboot your computer prior to uninstallation.
		$a_00_2 = {20 52 65 62 6f 6f 74 20 6e 6f 77 3f } //100  Reboot now?
		$a_01_3 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 69 6e 73 74 61 6c 6c 20 6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 2e } //100 This program install on your system antivirus software.
		$a_00_4 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 75 6e 69 6e 73 74 61 6c 6c 20 53 61 66 65 74 79 20 41 6c 65 72 74 65 72 } //100 Are you sure you want to uninstall Safety Alerter
		$a_00_5 = {66 72 6f 6d 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 3f } //100 from your computer?
		$a_00_6 = {44 6f 77 6e 6c 6f 61 64 20 6e 65 77 20 76 65 72 73 69 6f 6e 20 73 6f 66 74 77 61 72 65 20 66 6f 72 20 74 68 65 20 76 69 72 75 73 20 70 72 6f 74 65 63 74 69 6f 6e 2e } //100 Download new version software for the virus protection.
		$a_00_7 = {73 68 65 6c 6c 65 78 65 63 75 74 65 61 } //10 shellexecutea
		$a_00_8 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 77 69 6e 64 6f 77 73 } //10 rundll32.exe %s,windows
		$a_01_9 = {57 69 6e 64 6f 77 73 20 53 61 66 65 74 79 20 41 6c 65 72 74 } //10 Windows Safety Alert
		$a_00_10 = {77 69 6e 65 78 65 63 } //10 winexec
		$a_01_11 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //10 SeShutdownPrivilege
		$a_00_12 = {64 69 73 65 6e 66 72 61 6e 63 68 69 73 69 6e 67 } //1 disenfranchising
		$a_00_13 = {7b 65 32 62 38 63 65 61 31 2d 63 38 61 37 2d 34 38 65 32 2d 62 32 66 64 2d 38 39 61 65 35 63 36 30 38 66 62 38 7d } //1 {e2b8cea1-c8a7-48e2-b2fd-89ae5c608fb8}
		$a_00_14 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 73 68 61 72 65 64 74 61 73 6b 73 63 68 65 64 75 6c 65 72 } //1 software\microsoft\windows\currentversion\explorer\sharedtaskscheduler
		$a_00_15 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall
		$a_00_16 = {53 6f 66 74 77 61 72 65 4d 69 63 72 6f 73 6f 66 74 57 69 6e 64 6f 77 73 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //1 SoftwareMicrosoftWindowsCurrentVersionShellServiceObjectDelayLoad
		$a_00_17 = {25 73 20 2f 64 65 6c } //1 %s /del
		$a_00_18 = {2f 63 20 64 65 6c 20 25 73 20 20 20 3e 3e 20 20 20 4e 55 4c 4c } //1 /c del %s   >>   NULL
		$a_00_19 = {73 79 73 72 65 73 } //1 sysres
		$a_00_20 = {55 6e 69 6e 73 74 61 6c 6c 53 74 72 69 6e 67 } //1 UninstallString
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_01_3  & 1)*100+(#a_00_4  & 1)*100+(#a_00_5  & 1)*100+(#a_00_6  & 1)*100+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_01_9  & 1)*10+(#a_00_10  & 1)*10+(#a_01_11  & 1)*10+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1+(#a_00_20  & 1)*1) >=425
 
}