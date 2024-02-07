
rule Backdoor_Win32_Agent_CAA{
	meta:
		description = "Backdoor:Win32/Agent.CAA,SIGNATURE_TYPE_PEHSTR_EXT,3e 00 3e 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2f 61 6c 65 78 61 5f 63 6f 75 6e 74 2e 61 73 70 3f 75 72 6c 3d } //0a 00  /alexa_count.asp?url=
		$a_00_1 = {68 74 74 70 3a 2f 2f 61 6c 65 78 61 2e 76 65 72 79 6e 78 2e 63 6e } //0a 00  http://alexa.verynx.cn
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 41 6c 65 78 61 20 49 6e 74 65 72 6e 65 74 } //0a 00  SOFTWARE\Alexa Internet
		$a_00_3 = {5c 4d 73 66 33 73 66 2e 73 79 73 } //0a 00  \Msf3sf.sys
		$a_02_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 90 01 08 2e 45 58 45 90 00 } //0a 00 
		$a_00_5 = {28 00 43 00 29 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 } //01 00  (C) Microsoft Corporation. All rights reserved.
		$a_00_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Agent_CAA_2{
	meta:
		description = "Backdoor:Win32/Agent.CAA,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {70 69 6e 67 20 2d 6e 20 90 02 04 20 31 32 37 2e 30 2e 30 2e 31 20 3e 20 6e 75 6c 90 00 } //0a 00 
		$a_02_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 90 01 08 2e 45 58 45 90 00 } //0a 00 
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 65 6c 6d 65 2e 62 61 74 } //0a 00  C:\WINDOWS\SYSTEM32\delme.bat
		$a_00_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 67 67 6b 62 2e 62 61 74 } //0a 00  C:\WINDOWS\SYSTEM32\ggkb.bat
		$a_00_4 = {28 00 43 00 29 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 } //01 00  (C) Microsoft Corporation. All rights reserved.
		$a_00_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_00_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}