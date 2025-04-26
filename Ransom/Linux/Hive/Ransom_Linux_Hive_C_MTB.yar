
rule Ransom_Linux_Hive_C_MTB{
	meta:
		description = "Ransom:Linux/Hive.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {52 a9 e7 1c 8a e5 be 64 06 a5 e0 72 36 71 73 4f 16 5f 06 97 d6 b4 92 a1 51 25 fb 54 43 c7 49 24 0c 33 bc 04 7b 47 fd } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}