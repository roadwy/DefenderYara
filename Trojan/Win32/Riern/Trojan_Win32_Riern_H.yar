
rule Trojan_Win32_Riern_H{
	meta:
		description = "Trojan:Win32/Riern.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 32 32 cb 88 0c 2e 46 3b 74 24 ?? 0f 8c ?? ?? ?? ?? 5b } //1
		$a_03_1 = {8b c8 88 1c 29 89 7e ?? 5d 39 56 ?? 72 02 8b 00 c6 04 38 00 8b c6 } //1
		$a_01_2 = {8d 68 01 8d 49 00 8a 08 40 3a cb 75 f9 2b c5 50 } //1
		$a_03_3 = {c7 44 24 10 01 00 00 00 39 ?? ?? ?? 72 0a 8b ?? ?? ?? 89 ?? ?? ?? eb 08 8d ?? ?? ?? 89 [0-09] 8d ?? ?? ?? ?? 6a 01 ?? ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}