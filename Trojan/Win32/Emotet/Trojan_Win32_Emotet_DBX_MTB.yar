
rule Trojan_Win32_Emotet_DBX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 03 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 90 01 04 99 f7 f9 8a 45 00 8a 54 14 90 01 01 32 c2 88 45 00 8b 44 24 90 02 05 48 89 44 24 90 01 01 0f 85 90 00 } //01 00 
		$a_81_1 = {65 72 7a 47 47 57 47 34 74 67 32 7a 79 7a 65 } //01 00 
		$a_81_2 = {61 7a 67 61 34 61 67 33 67 33 71 67 } //01 00 
		$a_81_3 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //00 00 
	condition:
		any of ($a_*)
 
}