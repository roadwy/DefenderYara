
rule Trojan_Win32_Bandit_DHB_MTB{
	meta:
		description = "Trojan:Win32/Bandit.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f7 2b ee 8b 44 24 ?? d1 6c 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 29 } //1
		$a_02_1 = {8b f7 d3 e7 c1 ee 05 03 74 24 ?? 03 7c 24 ?? 33 f8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 0c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}