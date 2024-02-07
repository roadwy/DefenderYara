
rule Backdoor_Win32_Hupigon_A_MTB{
	meta:
		description = "Backdoor:Win32/Hupigon.A!MTB,SIGNATURE_TYPE_PEHSTR,29 00 29 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //0a 00  %SystemRoot%\system32\svchos.exe
		$a_01_1 = {61 64 64 2e 70 68 70 } //0a 00  add.php
		$a_01_2 = {69 6e 66 6f 2d 45 57 54 2e 64 6c 6c } //0a 00  info-EWT.dll
		$a_01_3 = {6c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  lexplorer.exe
		$a_01_4 = {6f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 2e 00 65 00 78 00 65 00 } //01 00  outlook.exe
		$a_01_5 = {6d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2e 00 65 00 78 00 65 00 } //01 00  mozilla.exe
		$a_01_6 = {66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00 } //00 00  firefox.exe
		$a_01_7 = {00 67 16 00 00 4c 6e b8 61 af 41 07 06 77 00 b3 5c 21 c6 00 00 01 } //20 77 
	condition:
		any of ($a_*)
 
}