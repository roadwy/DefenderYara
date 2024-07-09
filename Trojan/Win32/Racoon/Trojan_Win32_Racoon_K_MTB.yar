
rule Trojan_Win32_Racoon_K_MTB{
	meta:
		description = "Trojan:Win32/Racoon.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 36 23 01 00 01 45 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 55 ?? 03 55 ?? 8a 02 88 01 } //1
		$a_03_1 = {8b 45 08 8b 08 33 4d ?? 8b 55 ?? 89 0a } //1
		$a_03_2 = {c1 e2 04 89 55 [0-40] d3 e8 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? 8b 55 ?? 33 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}