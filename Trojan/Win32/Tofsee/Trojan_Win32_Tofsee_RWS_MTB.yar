
rule Trojan_Win32_Tofsee_RWS_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 03 4d 90 01 01 03 d6 33 c2 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 89 1d 90 01 04 89 1d 90 01 04 89 45 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}