
rule Trojan_Win32_SmokeLoader_AMAZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AMAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 ec c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}