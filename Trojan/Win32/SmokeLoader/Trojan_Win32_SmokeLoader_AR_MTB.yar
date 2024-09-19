
rule Trojan_Win32_SmokeLoader_AR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 8b 45 e8 01 45 fc 8b 4d f8 8b c7 c1 e0 ?? 03 45 ?? 03 cf 33 c1 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}