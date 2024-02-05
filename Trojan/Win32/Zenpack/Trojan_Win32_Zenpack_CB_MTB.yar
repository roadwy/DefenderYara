
rule Trojan_Win32_Zenpack_CB_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_03_0 = {ff d0 89 da 01 15 90 01 04 89 f0 01 05 90 01 04 55 8f 05 90 01 04 89 f8 01 05 90 01 04 eb d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_CB_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {49 89 ca 89 25 90 01 04 eb 05 e8 90 01 04 89 da 01 15 90 01 04 89 f0 01 05 90 01 04 55 8f 05 90 01 04 89 f8 01 05 90 01 04 eb da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_CB_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {55 89 e5 eb 1f 89 2d 90 01 04 58 a3 90 01 04 81 05 90 01 04 04 00 00 00 90 01 04 e8 90 01 04 89 d9 89 0d 90 01 04 89 f1 89 0d 90 01 04 89 3d 90 01 04 eb c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpack_CB_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpack.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_03_0 = {55 89 e5 eb 1f 89 2d 90 01 04 58 a3 90 01 04 81 05 90 01 04 04 00 00 00 66 6a 00 50 e8 90 01 04 89 d9 89 0d 90 01 04 89 f1 89 0d 90 01 04 89 3d 90 01 04 eb c9 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}