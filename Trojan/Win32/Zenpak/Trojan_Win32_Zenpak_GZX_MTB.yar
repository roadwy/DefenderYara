
rule Trojan_Win32_Zenpak_GZX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff d0 83 c2 03 89 e8 50 8f 05 90 01 04 8d 05 90 01 04 89 30 29 c2 ba 04 00 00 00 01 3d 90 01 04 8d 05 90 01 04 01 18 b9 02 00 00 00 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_GZX_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 e0 50 8f 05 90 01 04 48 b9 02 00 00 00 90 01 02 31 3d 90 01 04 89 1d 90 01 04 e8 90 01 04 b8 04 00 00 00 89 c2 31 35 90 01 04 31 2d 90 01 04 e8 90 01 04 89 45 90 01 01 55 89 e5 b8 01 00 00 00 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}