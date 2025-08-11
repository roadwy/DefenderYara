
rule Ransom_Win64_Akira_YAB_MTB{
	meta:
		description = "Ransom:Win64/Akira.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 61 00 72 00 69 00 6b 00 61 00 } //1 .arika
		$a_01_1 = {2e 00 76 00 68 00 64 00 78 00 } //1 .vhdx
		$a_01_2 = {48 89 ca 48 83 e2 03 44 8a 04 14 44 30 c0 88 04 0e 48 ff c1 4c 39 d1 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=12
 
}