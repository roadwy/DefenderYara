
rule Backdoor_Win32_Agent_FH{
	meta:
		description = "Backdoor:Win32/Agent.FH,SIGNATURE_TYPE_PEHSTR,20 00 20 00 09 00 00 "
		
	strings :
		$a_01_0 = {4f 75 74 70 6f 73 74 20 46 69 72 65 77 61 6c 6c } //10 Outpost Firewall
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_01_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //10 netsh firewall set allowedprogram
		$a_01_3 = {62 6f 74 6e 65 74 } //1 botnet
		$a_01_4 = {70 32 70 5f 77 6f 72 6d } //1 p2p_worm
		$a_01_5 = {73 70 6f 6f 6c 63 6f 6f 6c } //1 spoolcool
		$a_01_6 = {62 6f 74 4d 6f 64 75 6c 65 73 } //1 botModules
		$a_01_7 = {42 61 63 6b 44 6f 6f 72 2e 53 6e 6f 77 43 72 61 73 68 } //1 BackDoor.SnowCrash
		$a_01_8 = {4e 6f 72 74 6f 6e 20 41 76 20 63 72 61 63 6b 2e 65 78 65 } //1 Norton Av crack.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=32
 
}