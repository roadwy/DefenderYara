
rule Backdoor_Win32_Tofsee_BC_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cb 03 d3 c1 e9 05 03 8d 90 01 04 89 85 90 01 04 89 95 90 01 04 89 35 90 01 04 89 35 90 01 04 8b 85 90 01 04 31 85 90 01 04 81 3d 90 01 04 72 07 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}