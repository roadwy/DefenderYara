
rule Trojan_Win32_Zenpack_XF_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.XF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 03 44 24 ?? 33 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 0f 85 } //10
		$a_01_1 = {2e 70 64 62 } //1 .pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}