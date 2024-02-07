
rule TrojanSpy_Win32_Bancos_AHP{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHP,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 18 01 0d 00 00 64 00 "
		
	strings :
		$a_00_0 = {63 6c 73 5a 69 6d 62 6f 4e 65 77 73 } //64 00  clsZimboNews
		$a_00_1 = {61 00 7a 00 3a 00 5c 00 61 00 62 00 63 00 5c 00 61 00 62 00 63 00 2e 00 76 00 62 00 70 00 } //32 00  az:\abc\abc.vbp
		$a_01_2 = {57 73 6e 6b 78 5f 42 50 41 47 46 5f 6f 6e 63 6c 69 63 6b } //32 00  Wsnkx_BPAGF_onclick
		$a_00_3 = {63 6c 73 4b 69 74 6e 65 77 73 } //14 00  clsKitnews
		$a_01_4 = {49 45 5f 46 6f 72 61 5f 6f 6e 6b 65 79 75 70 } //14 00  IE_Fora_onkeyup
		$a_01_5 = {43 61 70 74 63 68 61 5f 44 6f 63 5f 45 6d 70 72 65 73 61 } //14 00  Captcha_Doc_Empresa
		$a_01_6 = {46 6c 61 73 68 20 50 6c 61 79 65 72 20 32 35 2e 30 20 72 33 } //14 00  Flash Player 25.0 r3
		$a_01_7 = {56 69 70 65 72 58 65 6f 6e } //0a 00  ViperXeon
		$a_01_8 = {45 7a 57 42 53 65 72 76 69 64 6f 72 } //0a 00  EzWBServidor
		$a_01_9 = {67 00 6f 00 76 00 2e 00 62 00 72 00 2f 00 53 00 49 00 49 00 42 00 43 00 2f 00 68 00 6f 00 6d 00 65 00 2e 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 61 00 } //0a 00  gov.br/SIIBC/home.processa
		$a_01_10 = {43 00 45 00 44 00 41 00 44 00 37 00 43 00 45 00 42 00 38 00 44 00 35 00 44 00 33 00 44 00 42 00 41 00 33 00 } //0a 00  CEDAD7CEB8D5D3DBA3
		$a_01_11 = {50 6c 61 6e 74 61 5f 41 6c 66 61 63 65 } //0a 00  Planta_Alface
		$a_01_12 = {45 78 74 72 61 74 6f 5f 43 43 } //00 00  Extrato_CC
	condition:
		any of ($a_*)
 
}