
rule Trojan_Win32_SmokeLoader_AXX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 03 44 24 ?? 33 44 24 ?? 33 c8 51 8b c6 89 4c 24 ?? e8 ?? ?? ?? ?? 8b f0 8d 44 24 ?? 89 74 ?? 24 e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}