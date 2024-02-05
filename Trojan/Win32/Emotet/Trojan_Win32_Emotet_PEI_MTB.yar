
rule Trojan_Win32_Emotet_PEI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 84 34 90 01 04 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8a 5c 24 90 01 01 8d 4c 24 90 01 01 8a 94 14 90 01 04 32 d3 88 55 90 00 } //01 00 
		$a_81_1 = {46 6b 6a 43 7a 70 53 73 34 43 4d 49 69 67 47 57 69 76 73 48 42 46 39 65 69 } //01 00 
		$a_81_2 = {4a 36 38 6b 43 51 73 68 59 37 7d 68 62 76 4f 24 69 57 70 31 46 4d 25 63 36 25 6c 79 70 32 6b 75 } //00 00 
	condition:
		any of ($a_*)
 
}