
rule Trojan_Win32_Qbot_SN_MTB{
	meta:
		description = "Trojan:Win32/Qbot.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0a 00 00 "
		
	strings :
		$a_81_0 = {46 69 64 64 6c 65 72 2e 65 78 65 3b 73 61 6d 70 31 65 2e 65 78 65 3b 73 61 6d 70 6c 65 2e 65 78 65 3b 72 75 6e 73 61 6d 70 6c 65 2e 65 78 65 3b 6c 6f 72 64 70 65 2e 65 78 65 3b 72 65 67 73 68 6f 74 2e 65 78 65 3b 41 75 74 6f 72 75 6e 73 2e 65 78 65 3b 64 73 6e 69 66 66 2e 65 78 65 3b 56 42 6f 78 54 72 61 79 2e 65 78 65 3b 48 61 73 68 4d 79 46 69 6c 65 73 2e 65 78 65 3b } //10 Fiddler.exe;samp1e.exe;sample.exe;runsample.exe;lordpe.exe;regshot.exe;Autoruns.exe;dsniff.exe;VBoxTray.exe;HashMyFiles.exe;
		$a_81_1 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 3b 50 72 6f 63 6d 6f 6e 2e 65 78 65 3b 50 72 6f 63 6d 6f 6e 36 34 2e 65 78 65 3b 6e 65 74 6d 6f 6e 2e 65 78 65 3b 76 6d 74 6f 6f 6c 73 64 2e 65 78 65 3b 76 6d 33 64 73 65 72 76 69 63 65 2e 65 78 65 3b 56 47 41 75 74 68 53 65 72 76 69 63 65 2e 65 78 65 3b 70 72 30 63 33 78 70 2e 65 78 65 3b 50 72 6f 63 65 73 73 48 61 63 6b 65 72 } //10 ProcessHacker.exe;Procmon.exe;Procmon64.exe;netmon.exe;vmtoolsd.exe;vm3dservice.exe;VGAuthService.exe;pr0c3xp.exe;ProcessHacker
		$a_81_2 = {43 46 46 20 45 78 70 6c 6f 72 65 72 2e 65 78 65 3b 64 75 6d 70 63 61 70 2e 65 78 65 3b 57 69 72 65 73 68 61 72 6b 2e 65 78 65 3b 69 64 61 71 2e 65 78 65 3b 69 64 61 71 36 34 2e 65 78 65 3b 54 50 41 75 74 6f 43 6f 6e 6e 65 63 74 2e 65 78 65 3b 52 65 73 6f 75 72 63 65 48 61 63 6b 65 72 2e 65 78 65 3b 76 6d 61 63 74 68 6c 70 2e 65 78 65 3b 4f 4c 4c 59 44 42 47 2e 45 58 45 3b } //10 CFF Explorer.exe;dumpcap.exe;Wireshark.exe;idaq.exe;idaq64.exe;TPAutoConnect.exe;ResourceHacker.exe;vmacthlp.exe;OLLYDBG.EXE;
		$a_81_3 = {62 64 73 2d 76 69 73 69 6f 6e 2d 61 67 65 6e 74 2d 6e 61 69 2e 65 78 65 3b 62 64 73 2d 76 69 73 69 6f 6e 2d 61 70 69 73 2e 65 78 65 3b 62 64 73 2d 76 69 73 69 6f 6e 2d 61 67 65 6e 74 2d 61 70 70 2e 65 78 65 3b 4d 75 6c 74 69 41 6e 61 6c 79 73 69 73 5f 76 31 2e 30 2e 32 39 34 2e 65 78 65 3b 78 33 32 64 62 67 2e 65 78 65 3b 56 42 6f 78 54 72 61 79 2e 65 78 65 3b 56 42 6f 78 53 65 } //10 bds-vision-agent-nai.exe;bds-vision-apis.exe;bds-vision-agent-app.exe;MultiAnalysis_v1.0.294.exe;x32dbg.exe;VBoxTray.exe;VBoxSe
		$a_03_4 = {8d 0c 10 8d 1c 0f 83 e3 ?? 8a 9b ?? ?? ?? ?? 32 1c 16 42 88 19 3b 55 fc 72 e6 } //1
		$a_03_5 = {50 ff 36 83 e9 05 c6 45 f4 e9 89 4d f5 c7 45 fc 05 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 78 1c } //1
		$a_81_6 = {52 4f 4f 54 5c 43 49 4d 56 32 } //1 ROOT\CIMV2
		$a_81_7 = {57 69 6e 33 32 5f 50 72 6f 63 65 73 73 } //1 Win32_Process
		$a_81_8 = {43 6f 6d 6d 61 6e 64 4c 69 6e 65 } //1 CommandLine
		$a_81_9 = {72 75 6e 61 73 } //1 runas
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=46
 
}