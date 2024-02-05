
rule Trojan_Win32_Tofsee_RM_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e2 04 89 90 01 02 8b 90 01 02 01 90 01 02 8b 90 01 02 03 90 01 02 89 90 01 02 c7 90 01 05 84 10 d6 cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Tofsee_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Tofsee.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d0 89 95 90 01 04 8b 8d 90 01 04 8b 95 90 01 04 31 11 83 c0 04 3b 85 90 01 04 7e 90 01 01 83 3d 90 02 08 75 90 01 01 83 3e 00 8b 07 3b 07 c7 85 90 01 04 04 00 00 00 81 3d 90 01 04 13 22 00 00 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}