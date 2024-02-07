
rule TrojanDownloader_Win32_Camec_G{
	meta:
		description = "TrojanDownloader:Win32/Camec.G,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0b 00 0b 00 00 05 00 "
		
	strings :
		$a_01_0 = {44 65 73 61 62 69 6c 69 74 61 5f 55 41 43 } //05 00  Desabilita_UAC
		$a_01_1 = {3b 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 } //02 00  ;Password=
		$a_01_2 = {6a 00 66 00 6c 00 61 00 73 00 68 00 2e 00 64 00 6c 00 6c 00 } //02 00  jflash.dll
		$a_01_3 = {5f 43 72 79 70 74 5f 53 65 6e 68 61 31 } //01 00  _Crypt_Senha1
		$a_01_4 = {47 72 61 76 61 5f 52 65 67 69 73 74 72 6f } //01 00  Grava_Registro
		$a_01_5 = {4c 65 72 5f 52 65 67 69 73 74 72 6f } //01 00  Ler_Registro
		$a_01_6 = {52 65 67 69 73 74 72 61 5f 42 48 4f } //01 00  Registra_BHO
		$a_01_7 = {45 6e 76 69 61 5f 41 76 69 73 6f } //01 00  Envia_Aviso
		$a_01_8 = {43 61 72 72 65 67 61 5f 44 69 63 } //01 00  Carrega_Dic
		$a_01_9 = {43 61 72 72 65 67 61 5f 44 61 64 6f 73 } //01 00  Carrega_Dados
		$a_01_10 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 48 00 65 00 6c 00 70 00 65 00 72 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 } //00 00  CurrentVersion\Explorer\Browser Helper Objects
	condition:
		any of ($a_*)
 
}