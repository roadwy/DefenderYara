
rule Trojan_Win32_SmokeLoader_BWM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 81 45 e0 ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}