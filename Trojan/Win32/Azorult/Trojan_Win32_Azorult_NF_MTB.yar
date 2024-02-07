
rule Trojan_Win32_Azorult_NF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 06 00 "
		
	strings :
		$a_02_0 = {30 06 47 3b fb 90 18 33 90 01 01 81 90 02 05 90 18 8b 90 02 03 8d 90 02 02 e8 90 00 } //01 00 
		$a_02_1 = {88 14 0f 3d 90 02 04 75 06 89 90 02 05 41 3b c8 90 18 8b 90 02 05 8a 90 02 06 8b 90 00 } //01 00 
		$a_02_2 = {5f 33 cd 5e e8 90 02 04 c9 c3 90 09 0d 00 e8 90 02 04 e8 90 02 04 8b 4d 90 00 } //01 00 
		$a_81_3 = {47 6c 6f 62 61 6c 41 6c 6c 6f 63 } //01 00  GlobalAlloc
		$a_81_4 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //01 00  MapViewOfFile
		$a_81_5 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //01 00  SetEndOfFile
		$a_81_6 = {45 71 75 61 6c 53 69 64 } //00 00  EqualSid
	condition:
		any of ($a_*)
 
}