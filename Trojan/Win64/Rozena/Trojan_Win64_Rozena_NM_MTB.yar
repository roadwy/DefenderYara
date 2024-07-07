
rule Trojan_Win64_Rozena_NM_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 15 e8 a9 02 03 00 48 8b 44 24 90 01 01 49 89 03 48 8b 4a 90 01 01 49 89 4b 08 48 89 42 90 01 01 48 c7 42 18 90 01 04 48 83 c4 18 90 00 } //3
		$a_03_1 = {48 89 44 24 90 01 01 48 89 5c 24 90 01 01 e8 78 e3 02 00 48 8b 44 24 90 01 01 48 8b 5c 24 90 01 01 e9 69 ff ff ff 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}