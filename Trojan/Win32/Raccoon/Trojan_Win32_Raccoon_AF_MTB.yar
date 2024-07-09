
rule Trojan_Win32_Raccoon_AF_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 33 44 24 18 c7 05 ?? ?? ?? ?? 00 00 00 00 33 f0 89 44 24 10 89 74 24 1c 8b 44 24 1c 01 05 ?? ?? ?? ?? 8b 44 24 1c 29 44 24 14 8b 4c 24 14 c1 e1 04 89 4c 24 10 8b 44 24 28 01 44 24 10 8b 44 24 14 03 44 24 20 89 44 24 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}