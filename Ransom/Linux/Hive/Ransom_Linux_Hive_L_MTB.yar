
rule Ransom_Linux_Hive_L_MTB{
	meta:
		description = "Ransom:Linux/Hive.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 39 d6 0f 86 30 03 00 00 8a 04 11 41 88 04 3c 48 ff c7 48 ff c2 48 89 d0 31 d2 48 f7 f6 48 83 ff 04 75 dc } //1
		$a_00_1 = {48 8b 03 48 83 f8 05 72 0f 49 f7 e4 48 85 c0 74 07 48 8b 7b 10 41 ff d5 48 8b 43 30 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}