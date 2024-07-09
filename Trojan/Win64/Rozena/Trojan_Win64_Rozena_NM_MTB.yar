
rule Trojan_Win64_Rozena_NM_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 15 e8 a9 02 03 00 48 8b 44 24 ?? 49 89 03 48 8b 4a ?? 49 89 4b 08 48 89 42 ?? 48 c7 42 18 ?? ?? ?? ?? 48 83 c4 18 } //3
		$a_03_1 = {48 89 44 24 ?? 48 89 5c 24 ?? e8 78 e3 02 00 48 8b 44 24 ?? 48 8b 5c 24 ?? e9 69 ff ff ff } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}