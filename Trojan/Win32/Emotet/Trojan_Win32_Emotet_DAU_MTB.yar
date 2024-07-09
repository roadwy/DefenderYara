
rule Trojan_Win32_Emotet_DAU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 09 81 c3 ?? ?? ?? ?? 0f b6 c9 01 f1 21 d9 8b 75 ?? 8a 0c 0e 8b 5d ?? 32 0c 3b 8b 7d ?? 8b 75 ?? 29 f7 8b 75 ?? 8b 5d ?? 88 0c 1e } //1
		$a_02_1 = {01 f9 8b 7d ?? 21 f9 8b 7d ?? 8a 1c 0f 8b 4d ?? 8b 55 ?? 32 1c 11 8b 4d ?? 88 1c 11 } //1
		$a_02_2 = {01 da 21 f2 8a 14 17 8b 75 ?? 8b 5d ?? 32 14 1e 8b 75 ?? 88 14 1e } //1
		$a_02_3 = {01 d1 8b 54 24 ?? 21 d1 8b 54 24 ?? 8a 0c 0a 8b 54 24 ?? 32 0c 32 8b 74 24 ?? 88 0c 1e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}