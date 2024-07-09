
rule Trojan_Win32_SmokeLoader_UNI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.UNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}