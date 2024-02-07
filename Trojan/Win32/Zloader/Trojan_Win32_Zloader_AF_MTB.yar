
rule Trojan_Win32_Zloader_AF_MTB{
	meta:
		description = "Trojan:Win32/Zloader.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 90 01 04 83 f9 90 01 01 0f 82 90 01 04 81 f9 90 01 04 73 13 0f ba 25 90 01 04 01 0f 82 90 01 04 e9 90 01 04 0f ba 25 90 01 04 01 73 09 f3 a4 90 00 } //01 00 
		$a_81_1 = {3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  :\Windows\iexplore.exe
		$a_03_2 = {5c 68 69 6c 6c 5c 44 61 6e 63 65 5c 90 02 04 5c 63 6f 6d 70 61 6e 79 5c 42 65 61 75 74 79 5c 6b 65 65 70 5c 53 63 61 6c 65 5c 90 02 04 5c 45 78 70 65 72 69 65 6e 63 65 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}