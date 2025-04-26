
rule Backdoor_Win32_Mokes_GXY_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 0c 33 83 ff 0f ?? ?? 8d 95 ?? ?? ?? ?? 52 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Backdoor_Win32_Mokes_GXY_MTB_2{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 66 c7 05 ?? ?? ?? ?? 6f 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 65 63 74 00 c6 05 ?? ?? ?? ?? 72 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Backdoor_Win32_Mokes_GXY_MTB_3{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 17 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 55 ?? 8b 4d ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 4d ?? 33 c8 2b d9 89 4d ?? 8b c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Backdoor_Win32_Mokes_GXY_MTB_4{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 c9 89 45 ?? 89 4d ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}