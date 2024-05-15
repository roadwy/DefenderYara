
rule Trojan_Win64_NetLoader_DA_MTB{
	meta:
		description = "Trojan:Win64/NetLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //0a 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {34 00 33 00 38 00 32 00 2e 00 62 00 69 00 6d 00 6d 00 6f 00 62 00 69 00 6c 00 2e 00 78 00 79 00 7a 00 } //01 00  4382.bimmobil.xyz
		$a_03_2 = {2f 00 70 00 6c 00 61 00 79 00 2f 00 90 02 0f 2e 00 70 00 68 00 70 00 90 00 } //01 00 
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}