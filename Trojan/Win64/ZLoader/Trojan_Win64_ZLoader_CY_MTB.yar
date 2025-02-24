
rule Trojan_Win64_ZLoader_CY_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 2b c8 48 0f af cb 0f b6 44 0c 20 43 32 44 13 ff 41 88 42 ff 41 81 f9 c1 e0 01 00 72 } //3
		$a_01_1 = {33 c9 41 b8 00 30 00 00 42 8b 54 20 50 44 8d 49 40 48 81 c2 80 c3 c9 01 ff d7 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}