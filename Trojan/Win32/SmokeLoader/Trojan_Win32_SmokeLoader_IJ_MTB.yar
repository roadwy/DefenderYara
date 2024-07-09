
rule Trojan_Win32_SmokeLoader_IJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.IJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b d8 89 45 ?? 89 5d ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}