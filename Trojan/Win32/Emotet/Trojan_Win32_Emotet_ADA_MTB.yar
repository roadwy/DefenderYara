
rule Trojan_Win32_Emotet_ADA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {56 57 8b 7d ?? 33 d2 c7 45 ?? ?? ?? ?? 00 8b 45 ?? f7 f1 6a 11 89 45 } //1
		$a_03_1 = {80 3b 00 75 ?? 5f 5e 8b 45 ?? 5b 8b e5 5d c3 } //1
		$a_03_2 = {80 3b 00 75 ?? 5f 8b 45 ?? 5e 5b 8b e5 5d c3 } //1
		$a_03_3 = {0f be 03 89 45 ?? 01 75 ?? d3 e2 01 55 ?? 29 7d ?? 43 } //1
		$a_03_4 = {d3 e6 8a 4d ?? 8b 55 90 0a 50 00 8a 4d ?? 8b 75 [0-50] 81 75 } //1
		$a_03_5 = {80 3b 00 74 [0-04] 57 8b 7d ?? 33 d2 c7 45 ?? ?? ?? ?? ?? 8b 45 f8 f7 f1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}