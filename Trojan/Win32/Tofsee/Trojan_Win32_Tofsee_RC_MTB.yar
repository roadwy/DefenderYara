
rule Trojan_Win32_Tofsee_RC_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {c1 ee 05 33 c8 03 b4 24 90 01 04 0f 57 c0 81 3d 90 01 04 72 07 00 00 66 0f 13 05 90 01 04 89 4c 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}