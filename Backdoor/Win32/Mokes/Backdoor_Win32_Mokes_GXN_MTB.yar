
rule Backdoor_Win32_Mokes_GXN_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 13 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 4d ?? 33 db 33 4d ?? 8b 45 ?? 03 45 ?? 33 c1 89 4d ?? 8b 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}