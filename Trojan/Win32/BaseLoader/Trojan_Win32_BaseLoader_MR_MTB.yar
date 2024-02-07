
rule Trojan_Win32_BaseLoader_MR_MTB{
	meta:
		description = "Trojan:Win32/BaseLoader.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 02 02 28 90 02 04 06 6f 90 02 04 72 90 02 04 72 90 02 04 72 90 02 04 28 90 02 05 28 90 02 04 72 90 02 05 28 90 02 04 26 2a 90 09 21 00 02 03 72 90 02 04 72 90 02 04 72 90 02 04 28 90 02 04 16 28 90 02 04 74 90 00 } //01 00 
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_81_2 = {53 74 61 72 74 73 57 69 74 68 } //01 00  StartsWith
		$a_81_3 = {45 6e 64 73 57 69 74 68 } //01 00  EndsWith
		$a_81_4 = {54 6f 43 68 61 72 } //01 00  ToChar
		$a_81_5 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_6 = {54 6f 42 79 74 65 } //01 00  ToByte
		$a_81_7 = {54 6f 49 6e 74 33 32 } //00 00  ToInt32
	condition:
		any of ($a_*)
 
}