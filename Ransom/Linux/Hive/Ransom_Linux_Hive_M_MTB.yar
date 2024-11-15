
rule Ransom_Linux_Hive_M_MTB{
	meta:
		description = "Ransom:Linux/Hive.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 07 48 83 f8 05 72 ?? 48 8b 47 18 48 85 c0 74 ?? 48 8b 4f 10 48 8d 0c c1 48 83 c1 f8 } //1
		$a_03_1 = {48 8b 5c 24 10 49 89 ef ?? ?? 6c 24 18 48 89 df ff 55 00 48 83 7d 08 00 4c 89 fd 74 ?? 48 89 df } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}