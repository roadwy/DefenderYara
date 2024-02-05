
rule Trojan_Win32_Emotet_DGL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 8c 8a 4c 15 90 30 08 } //01 00 
		$a_81_1 = {59 25 6f 6c 54 35 73 4b 5a 64 40 7c 7e 52 34 63 58 57 69 74 72 7b } //01 00 
		$a_81_2 = {77 75 79 76 62 68 69 72 68 62 72 69 68 72 67 62 72 6b 62 72 6b 68 72 } //00 00 
	condition:
		any of ($a_*)
 
}