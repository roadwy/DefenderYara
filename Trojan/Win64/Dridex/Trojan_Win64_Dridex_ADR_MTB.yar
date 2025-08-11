
rule Trojan_Win64_Dridex_ADR_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 48 8b 4c 24 40 48 81 c1 ?? ?? ?? ?? 89 44 24 4c 8a 54 24 03 80 f2 ff 4c 8b 44 24 28 88 54 24 37 8a 54 24 03 80 f2 d7 4c 8b 4c 24 20 47 8a 14 01 88 54 24 37 4c 8b 5c 24 10 47 88 14 03 66 8b 34 24 66 81 ce 07 0d 49 01 c8 } //2
		$a_01_1 = {45 6f 66 6b 69 77 65 72 65 7a 34 } //1 Eofkiwerez4
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win64_Dridex_ADR_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 29 d1 66 44 8b 44 24 ?? 66 45 21 c0 66 44 89 84 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 66 44 8b 44 24 ?? 66 41 83 f0 ff 66 44 89 84 24 ?? ?? ?? ?? 4c 8b 4c 24 } //1
		$a_01_1 = {44 29 c2 44 8b 4c 24 28 89 54 24 3c 44 8a 54 24 39 66 44 8b 5c 24 22 66 44 89 5c 24 3a 41 80 f2 28 c6 44 24 4f 18 8a 5c 24 39 48 8b 44 24 18 48 83 f0 ff } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}