
rule Trojan_Win64_Emotet_DF_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb 03 d3 ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 0a ?? 41 88 49 ?? 48 83 ef 01 74 } //1
		$a_01_1 = {74 4b 39 25 36 54 59 65 43 69 4e 37 52 3e 52 32 77 24 67 42 53 5e 31 62 48 55 66 30 4e } //1 tK9%6TYeCiN7R>R2w$gBS^1bHUf0N
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}