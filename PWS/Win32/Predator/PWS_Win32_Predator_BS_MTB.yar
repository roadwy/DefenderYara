
rule PWS_Win32_Predator_BS_MTB{
	meta:
		description = "PWS:Win32/Predator.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e1 04 03 8d 90 01 04 03 d3 89 8d 90 01 04 8b cb c1 e9 05 03 8d 90 01 04 c7 05 90 01 08 89 95 90 01 04 89 3d 90 01 04 89 3d 90 01 04 8b 85 90 01 04 31 85 90 01 04 81 3d 90 01 04 72 07 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}