
rule Trojan_Win32_Redline_JC_MTB{
	meta:
		description = "Trojan:Win32/Redline.JC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 e2 89 5d ?? 03 55 ?? 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 } //1
		$a_03_1 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 33 4d ?? 8b 45 ?? 33 c1 2b f8 89 45 ?? 89 1d ?? ?? ?? ?? 89 7d ?? 8b 45 ?? 29 45 ?? 83 6d d8 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}