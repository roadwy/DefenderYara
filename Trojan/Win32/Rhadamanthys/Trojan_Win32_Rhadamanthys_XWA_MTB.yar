
rule Trojan_Win32_Rhadamanthys_XWA_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.XWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 8d 34 2f c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 18 8b 44 24 28 01 44 24 18 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 4c 24 38 51 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 54 24 18 8b 44 24 14 33 d6 33 c2 2b d8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 14 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}