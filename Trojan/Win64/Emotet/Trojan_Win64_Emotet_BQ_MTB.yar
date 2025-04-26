
rule Trojan_Win64_Emotet_BQ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 83 c1 ?? 48 63 c9 0f b6 0c 01 43 32 4c 13 ?? 41 88 4a ?? 48 83 ef ?? 74 } //2
		$a_03_1 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08 49 ff c0 49 83 eb ?? 74 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}