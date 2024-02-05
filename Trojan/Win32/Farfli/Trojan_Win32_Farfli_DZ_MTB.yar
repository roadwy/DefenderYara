
rule Trojan_Win32_Farfli_DZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {6a 65 73 73 6f 2e 33 33 32 32 2e 6f 72 67 } //jesso.3322.org  01 00 
		$a_80_1 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 25 73 25 64 2e 65 78 65 } //c:\Windows\%s%d.exe  01 00 
		$a_80_2 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 42 4a 2e 65 78 65 } //c:\Windows\BJ.exe  01 00 
		$a_80_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //GetTickCount  01 00 
		$a_80_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //URLDownloadToFileA  00 00 
	condition:
		any of ($a_*)
 
}