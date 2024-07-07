
rule Trojan_Win32_CobaltStrike_TB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 63 c0 46 8a 04 02 41 b9 90 01 04 31 d2 41 f7 f1 8b 44 24 90 01 01 41 89 d1 48 8b 54 24 90 01 01 4d 63 c9 46 32 04 0a 48 63 d0 44 88 04 11 83 c0 01 31 c9 89 ca 48 b9 90 01 08 48 29 ca 31 c9 49 b8 90 01 08 4c 29 c1 83 f8 90 01 01 48 0f 44 ca 90 00 } //1
		$a_01_1 = {2f 00 6d 00 6f 00 64 00 65 00 6c 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 } //1 /model/install.php
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_CobaltStrike_TB_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 } //10 C:\Users\Public
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {4e 65 77 57 59 44 6c 6c 5c 4e 65 77 57 59 44 6c 6c 5c 52 65 6c 65 61 73 65 5c 4e 65 77 57 59 44 6c 6c 2e 70 64 62 } //10 NewWYDll\NewWYDll\Release\NewWYDll.pdb
		$a_01_3 = {25 73 5c 75 70 64 61 74 65 72 2e 65 78 65 } //10 %s\updater.exe
		$a_01_4 = {25 73 5c 6c 69 62 63 75 72 6c 2e 64 6c 6c } //1 %s\libcurl.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1) >=32
 
}