
rule Trojan_Win64_CobaltStrike_OPZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f1 c1 e9 02 f3 0f 10 44 24 ?? 49 89 d8 49 8d 40 04 f3 41 0f 10 08 0f 57 c8 f3 41 0f 11 08 49 89 c0 ff c9 75 } //4
		$a_03_1 = {89 c9 45 31 c0 46 8a 4c 04 ?? 46 30 0c 00 49 ff c0 4c 39 c1 75 } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}