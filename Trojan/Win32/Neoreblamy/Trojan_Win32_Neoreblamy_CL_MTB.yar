
rule Trojan_Win32_Neoreblamy_CL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 04 0a 33 c6 69 f0 93 01 00 01 42 83 fa 04 72 ee } //01 00 
		$a_00_1 = {33 d2 8b c6 6a 0e 59 f7 f1 8b 45 08 8b 0c b3 8b 14 90 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46 3b f7 72 dc } //01 00 
		$a_01_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}