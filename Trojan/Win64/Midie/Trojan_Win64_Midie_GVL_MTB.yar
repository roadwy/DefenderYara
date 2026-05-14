
rule Trojan_Win64_Midie_GVL_MTB{
	meta:
		description = "Trojan:Win64/Midie.GVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 b9 12 85 28 a7 41 0f b6 c9 66 44 0f af c9 8b 4c 0b ee 41 81 e9 ac 85 04 b6 41 51 80 74 24 06 1c 48 81 d3 04 00 00 00 41 c1 e9 2f 0f 84 12 d1 ff ff } //3
		$a_01_1 = {80 6c 5c 01 3f 0a 1c 19 80 74 24 01 29 } //1
		$a_01_2 = {32 44 24 09 1a c4 66 8b 04 22 49 81 da 02 00 00 00 e9 d2 ea ff ff } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}