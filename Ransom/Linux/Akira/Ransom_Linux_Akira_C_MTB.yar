
rule Ransom_Linux_Akira_C_MTB{
	meta:
		description = "Ransom:Linux/Akira.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8d 7e 20 49 83 c6 10 e8 ad ?? ?? ?? 48 8b 7c 24 30 4c 39 f7 ?? ?? e8 a6 a0 0b 00 48 89 df e8 be ?? ?? ?? 48 8d 7d 20 48 83 c5 10 e8 89 f9 06 00 48 8b 7c 24 20 48 39 ef ?? ?? e8 82 a0 0b 00 4c 89 e7 } //1
		$a_01_1 = {48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 28 08 00 00 89 bd bc f7 ff ff 48 89 b5 b0 f7 ff ff 48 8d 85 00 f9 ff ff 48 89 c7 e8 0f ca 00 00 48 8b 95 b0 f7 ff ff 8b b5 bc f7 ff ff 48 8d 85 00 f9 ff ff b9 01 00 00 00 48 89 c7 e8 32 bd 00 00 48 c7 85 60 fb ff ff a3 24 62 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}