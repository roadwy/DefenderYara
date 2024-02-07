
rule Trojan_Win32_RedLineStealer_MZA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 90 01 04 88 0c 02 c9 c2 90 00 } //01 00 
		$a_01_1 = {4c 6f 63 6b 46 69 6c 65 } //01 00  LockFile
		$a_01_2 = {43 72 65 61 74 65 4d 61 69 6c 73 6c 6f 74 41 } //01 00  CreateMailslotA
		$a_01_3 = {44 65 62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 } //01 00  DebugActiveProcess
		$a_01_4 = {47 65 74 43 6f 6d 70 72 65 73 73 65 64 46 69 6c 65 53 69 7a 65 57 } //00 00  GetCompressedFileSizeW
	condition:
		any of ($a_*)
 
}