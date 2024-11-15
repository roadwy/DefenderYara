
rule Trojan_Win64_Dridex_ADR_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ADR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 29 d1 66 44 8b 44 24 ?? 66 45 21 c0 66 44 89 84 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 66 44 8b 44 24 ?? 66 41 83 f0 ff 66 44 89 84 24 ?? ?? ?? ?? 4c 8b 4c 24 } //1
		$a_01_1 = {44 29 c2 44 8b 4c 24 28 89 54 24 3c 44 8a 54 24 39 66 44 8b 5c 24 22 66 44 89 5c 24 3a 41 80 f2 28 c6 44 24 4f 18 8a 5c 24 39 48 8b 44 24 18 48 83 f0 ff } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}