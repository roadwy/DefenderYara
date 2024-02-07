
rule Trojan_BAT_Ader_SPQ_MTB{
	meta:
		description = "Trojan:BAT/Ader.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {4c 6f 67 69 6e 44 61 6f 43 6f 6d 61 6e 64 6f 73 } //01 00  LoginDaoComandos
		$a_81_1 = {42 65 6d 76 69 6e 64 6f 5f 4c 6f 61 64 } //01 00  Bemvindo_Load
		$a_81_2 = {54 65 6c 61 5f 50 72 6f 6a 65 74 } //01 00  Tela_Projet
		$a_81_3 = {54 65 6c 61 5f 50 72 6f 6a 65 74 2e 44 41 4c } //01 00  Tela_Projet.DAL
		$a_81_4 = {54 65 6c 61 5f 50 72 6f 6a 65 74 2e 4d 4f 44 45 4c 4f } //01 00  Tela_Projet.MODELO
		$a_01_5 = {45 00 72 00 72 00 6f 00 20 00 63 00 6f 00 6d 00 20 00 42 00 61 00 6e 00 63 00 6f 00 20 00 64 00 65 00 20 00 44 00 61 00 64 00 6f 00 73 00 21 00 } //01 00  Erro com Banco de Dados!
		$a_01_6 = {6d 00 61 00 72 00 74 00 69 00 6e 00 73 00 72 00 6c 00 6b 00 23 00 37 00 35 00 34 00 35 00 } //00 00  martinsrlk#7545
	condition:
		any of ($a_*)
 
}