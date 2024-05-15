
rule Backdoor_Win32_Mokes_GXY_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 66 c7 05 90 01 04 6f 74 c7 05 90 01 04 75 61 6c 50 c7 05 90 01 04 65 63 74 00 c6 05 90 01 04 72 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Mokes_GXY_MTB_2{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 04 17 89 45 90 01 01 8b 45 90 01 01 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 55 90 01 01 8b 4d 90 01 01 c7 05 90 01 04 ee 3d ea f4 e8 90 01 04 8b 4d 90 01 01 33 c8 2b d9 89 4d 90 01 01 8b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Mokes_GXY_MTB_3{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 03 c6 89 45 90 01 01 8b c6 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 33 c9 89 45 90 01 01 89 4d 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}