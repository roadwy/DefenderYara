
rule Trojan_Win32_SmokeLoader_GDM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {78 36 35 3d 81 6d ?? db 66 3b 70 8b 45 ?? 8b 4d ?? 31 08 } //10
		$a_03_1 = {8b c3 c1 e0 ?? 89 5d ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? ff 75 ?? 83 0d ?? ?? ?? ?? ?? 8b c3 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}