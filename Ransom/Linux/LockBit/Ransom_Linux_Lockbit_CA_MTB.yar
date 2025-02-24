
rule Ransom_Linux_Lockbit_CA_MTB{
	meta:
		description = "Ransom:Linux/Lockbit.CA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 57 41 56 41 55 41 54 49 89 d5 53 48 89 cb 48 81 ec 48 07 00 00 4d 85 c0 48 89 bd 00 f9 ff ff 4c 89 85 08 f9 ff ff 4c 89 8d e8 f8 ff ff 4c 8b 7d 10 75 08 } //1
		$a_01_1 = {e8 fb 9f ff ff 44 8b 18 44 89 df 44 89 5c 24 1c e8 db a5 ff ff 48 89 44 24 10 e8 71 a4 ff ff 4c 8b 4c 24 10 44 8b 44 24 1c 48 8d 74 24 38 48 89 c2 89 d9 bf 80 11 61 00 31 c0 e8 d1 62 00 00 eb 1c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}