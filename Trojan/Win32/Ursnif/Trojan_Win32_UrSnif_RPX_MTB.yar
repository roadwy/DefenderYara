
rule Trojan_Win32_UrSnif_RPX_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 d2 74 01 ea 31 1a 81 ee 01 00 00 00 68 21 34 a3 ec 58 81 c2 04 00 00 00 01 f8 39 ca 75 e1 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_UrSnif_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 db 0f 84 50 00 00 00 56 89 2c 24 89 14 24 68 00 00 00 00 5a 01 c2 50 b8 00 00 00 00 01 d0 01 08 58 5a 83 ec 04 89 14 24 } //00 00 
	condition:
		any of ($a_*)
 
}