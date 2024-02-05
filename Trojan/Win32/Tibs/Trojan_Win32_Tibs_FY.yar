
rule Trojan_Win32_Tibs_FY{
	meta:
		description = "Trojan:Win32/Tibs.FY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f c8 b9 b9 34 ab 00 eb 00 81 e9 11 32 ab 00 68 90 01 04 5a 01 c2 52 87 02 05 90 01 04 6a 02 6a 02 e8 90 01 03 ff e2 ee c3 90 00 } //01 00 
		$a_01_1 = {bf c1 3e 5c f1 ff b4 0f 21 63 e4 0e e8 dc ff ff ff eb 00 } //01 00 
		$a_01_2 = {55 89 e5 87 02 03 55 08 03 55 0c c9 c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}