
rule Ransom_Linux_Conti_B_MTB{
	meta:
		description = "Ransom:Linux/Conti.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 89 c2 48 8d 05 df 17 00 00 48 89 c6 48 89 d7 e8 af e8 ff ff 48 89 45 e8 48 83 7d e8 00 74 2c 48 8b 45 e8 48 89 c1 ba af 0f 00 00 be 01 00 00 00 48 8d 05 ac 07 00 00 48 89 c7 e8 24 e9 ff ff 48 8b 45 e8 48 89 c7 } //01 00 
		$a_00_1 = {45 6e 74 72 61 6e 64 6f 20 61 20 72 75 74 61 3a 20 25 73 } //01 00  Entrando a ruta: %s
		$a_00_2 = {2d 2d 49 6e 69 63 69 61 6e 64 6f 20 45 6e 63 72 69 70 74 61 63 69 6f 6e 2d 2d } //01 00  --Iniciando Encriptacion--
		$a_00_3 = {55 48 89 e5 89 7d ec 89 75 e8 8b 45 ec 99 f7 7d e8 89 55 fc 83 7d fc 00 75 05 8b 45 e8 eb 0e 8b 45 e8 89 45 ec 8b 45 fc 89 45 e8 eb dd 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}