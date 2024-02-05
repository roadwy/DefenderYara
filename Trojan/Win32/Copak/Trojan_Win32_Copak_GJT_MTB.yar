
rule Trojan_Win32_Copak_GJT_MTB{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 13 01 f8 21 ff 43 4f 81 c7 90 01 04 81 c0 90 01 04 39 f3 75 90 01 01 21 f8 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Copak_GJT_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 59 81 c1 90 01 04 31 1f 47 81 c1 90 01 04 39 d7 75 90 01 01 c3 81 c6 90 01 04 8d 1c 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Copak_GJT_MTB_3{
	meta:
		description = "Trojan:Win32/Copak.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 34 24 83 c4 90 01 01 e8 90 01 04 81 c3 90 01 04 83 ec 90 01 01 89 14 24 5a 31 37 21 da 47 81 ea 90 01 04 29 db 39 cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}