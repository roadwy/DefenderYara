
rule Trojan_Win32_Tofsee_RB_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 55 90 01 01 66 0f 57 c0 66 0f 13 05 90 01 04 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 81 3d 90 01 04 72 07 00 00 75 90 00 } //02 00 
		$a_02_1 = {c1 e8 05 89 90 01 02 66 0f 57 c0 66 0f 13 05 90 01 04 8b 90 01 02 03 90 01 02 89 90 01 02 8b 90 01 02 33 90 01 02 89 90 01 02 81 3d 90 01 04 72 07 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}