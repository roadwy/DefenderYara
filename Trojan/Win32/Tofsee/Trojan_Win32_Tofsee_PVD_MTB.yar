
rule Trojan_Win32_Tofsee_PVD_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 33 c6 89 44 24 10 2b f8 8b 44 24 90 01 01 d1 6c 24 90 01 01 29 44 24 90 01 01 83 6c 24 90 01 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}