
rule Trojan_Win32_Bandit_MP_MTB{
	meta:
		description = "Trojan:Win32/Bandit.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 56 ff 15 ?? ?? ?? ?? 8b 4c 24 70 8b 54 24 1c 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b f7 c1 ee 05 03 74 24 68 03 d9 03 d7 33 da 81 3d ?? ?? ?? ?? 72 07 00 00 75 53 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}