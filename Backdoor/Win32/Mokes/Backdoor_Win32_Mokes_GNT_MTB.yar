
rule Backdoor_Win32_Mokes_GNT_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 ?? 03 74 24 ?? 8d 04 1f 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}