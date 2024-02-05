
rule Trojan_Win32_Tibs_HX{
	meta:
		description = "Trojan:Win32/Tibs.HX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 c3 58 59 5a 69 db 00 00 01 00 01 df 83 ef 01 83 ef 01 83 ef 02 81 ef 00 70 00 00 81 ef 00 60 00 00 81 ef 00 30 00 00 e2 b7 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Tibs_HX_2{
	meta:
		description = "Trojan:Win32/Tibs.HX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 83 e8 03 29 c2 49 eb 90 01 01 89 d7 85 c9 74 02 29 c9 81 c1 90 90 4c 00 00 e8 90 01 01 ff ff ff 59 eb 90 01 01 e8 90 01 01 ff ff ff 90 09 08 00 90 02 02 c3 51 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}