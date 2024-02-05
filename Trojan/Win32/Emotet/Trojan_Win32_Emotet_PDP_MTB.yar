
rule Trojan_Win32_Emotet_PDP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 03 c1 b9 90 01 04 99 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 08 90 09 08 00 0f b6 8c 05 90 00 } //01 00 
		$a_81_1 = {63 68 71 69 54 72 5a 71 69 6f 51 39 57 66 70 4a 43 45 5a 6b 5a 78 42 46 6a 62 41 6e 72 65 7a 73 45 58 67 5a 46 55 57 42 } //00 00 
	condition:
		any of ($a_*)
 
}