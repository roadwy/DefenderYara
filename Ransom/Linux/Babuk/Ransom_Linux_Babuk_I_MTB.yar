
rule Ransom_Linux_Babuk_I_MTB{
	meta:
		description = "Ransom:Linux/Babuk.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {74 2c 8b 45 0c 8b 55 f4 89 54 24 0c 89 44 24 08 c7 44 24 04 01 00 00 00 8b 45 08 89 04 24 e8 4f fe ff ff 8b 45 f4 89 04 24 e8 f4 fc ff ff c9 } //1
		$a_00_1 = {55 89 e5 53 83 ec 34 8b 45 08 89 45 e0 8b 45 0c 89 45 e4 b8 14 00 00 00 89 04 24 e8 a2 fd ff ff 89 45 e8 c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 10 c7 45 ec 00 00 00 00 e9 fd 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}