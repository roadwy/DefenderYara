
rule Trojan_Win32_SmokeLoader_KX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 8b 4d ?? 8b de d3 e3 03 45 ?? 89 55 ?? 89 45 ?? 03 5d ?? 33 d8 33 da 89 5d ?? 33 db 89 1d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 45 ?? ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}