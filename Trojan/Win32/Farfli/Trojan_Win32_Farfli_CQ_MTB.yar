
rule Trojan_Win32_Farfli_CQ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 61 69 64 69 73 68 69 6a 69 65 2e 33 33 32 32 2e 6f 72 67 } //01 00  haidishijie.3322.org
		$a_80_1 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 25 73 25 64 2e 65 78 65 } //c:\Windows\%s%d.exe  01 00 
		$a_80_2 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 42 4a 2e 65 78 65 } //c:\Windows\BJ.exe  01 00 
		$a_80_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //URLDownloadToFileA  01 00 
		$a_80_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //GetTickCount  01 00 
		$a_01_5 = {75 6e 6b 6e 6f 77 6e 20 63 6f 6d 70 72 65 73 73 69 6f 6e 20 6d 65 74 68 6f 64 } //01 00  unknown compression method
		$a_01_6 = {53 48 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 50 61 74 68 41 } //00 00  SHGetSpecialFolderPathA
	condition:
		any of ($a_*)
 
}