
rule Trojan_Win32_RedLineStealer_PI_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 2d 30 99 c7 02 8b 44 24 20 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 20 c1 e8 ?? 89 44 24 10 8b 44 24 10 03 44 24 44 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 44 24 14 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}