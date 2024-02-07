
rule Trojan_Win32_Agent_NAM{
	meta:
		description = "Trojan:Win32/Agent.NAM,SIGNATURE_TYPE_PEHSTR,2b 00 2b 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 53 6b 79 70 65 43 6c 69 65 6e 74 2e 65 78 65 } //0a 00  \SkypeClient.exe
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //0a 00  ShellExecuteA
		$a_01_3 = {5c 77 69 6e 69 6e 69 74 2e 69 6e 69 } //01 00  \wininit.ini
		$a_01_4 = {5c 6d 79 5f 37 30 30 30 38 2e 65 78 65 } //01 00  \my_70008.exe
		$a_01_5 = {5c 73 30 32 2e 65 78 65 } //01 00  \s02.exe
		$a_01_6 = {5c 64 6f 64 6f 6c 6f 6f 6b 33 34 39 2e 65 78 65 } //01 00  \dodolook349.exe
		$a_01_7 = {5c 61 64 5f 32 33 37 34 2e 65 78 65 } //01 00  \ad_2374.exe
		$a_01_8 = {5c 73 65 74 75 70 31 31 36 36 2e 65 78 65 } //01 00  \setup1166.exe
		$a_01_9 = {5c 73 68 75 69 67 65 6e 65 74 5f 63 62 2e 65 78 65 } //00 00  \shuigenet_cb.exe
	condition:
		any of ($a_*)
 
}