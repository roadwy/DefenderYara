
rule Trojan_Win32_SmokeLoader_KY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d ?? 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 2b 4d ?? 89 4d ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}