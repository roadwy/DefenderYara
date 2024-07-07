
rule Ransom_Linux_Hive_A_MTB{
	meta:
		description = "Ransom:Linux/Hive.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8a 0c 02 30 8c 04 90 00 00 00 48 8d 48 01 48 89 c8 48 83 f9 04 75 e9 } //1
		$a_00_1 = {48 89 ef e8 a3 0f 04 00 88 84 1c 50 01 00 00 48 ff c3 48 83 fb 08 75 e8 } //1
		$a_01_2 = {76 6d 64 6b } //1 vmdk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}