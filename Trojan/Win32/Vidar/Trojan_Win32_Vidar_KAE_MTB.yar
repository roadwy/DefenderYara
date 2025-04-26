
rule Trojan_Win32_Vidar_KAE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d7 8b 44 24 ?? c1 e8 05 89 44 24 ?? 8b 44 24 ?? 03 c5 33 c2 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}