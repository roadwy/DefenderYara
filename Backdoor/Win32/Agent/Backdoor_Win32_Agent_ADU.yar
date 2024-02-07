
rule Backdoor_Win32_Agent_ADU{
	meta:
		description = "Backdoor:Win32/Agent.ADU,SIGNATURE_TYPE_PEHSTR,2b 00 2b 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {62 65 6e 73 6f 72 74 79 2e 64 6c 6c } //0a 00  bensorty.dll
		$a_01_1 = {68 74 74 70 3a 2f 2f 79 75 6f 69 6f 70 2e 69 6e 66 6f 2f 72 64 2f 72 64 2e 70 68 70 } //0a 00  http://yuoiop.info/rd/rd.php
		$a_01_2 = {68 74 74 70 3a 2f 2f 6e 61 6e 6f 61 74 6f 6d 2e 69 6e 66 6f 2f 72 64 2f 72 64 2e 70 68 70 } //0a 00  http://nanoatom.info/rd/rd.php
		$a_01_3 = {7b 38 44 35 38 34 39 41 32 2d 39 33 46 33 2d 34 32 39 44 2d 46 46 33 34 2d 32 36 30 41 32 30 36 38 38 39 37 43 7d } //01 00  {8D5849A2-93F3-429D-FF34-260A2068897C}
		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
	condition:
		any of ($a_*)
 
}