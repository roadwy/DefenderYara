
rule TrojanSpy_Win32_Brajur_A{
	meta:
		description = "TrojanSpy:Win32/Brajur.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 13 00 00 0a 00 "
		
	strings :
		$a_03_0 = {a5 a5 a4 5e 46 ff 4d dc 0f 85 90 01 02 ff ff 6a 00 6a 5b 6a 5d 6a 00 8b 4d 90 00 } //0a 00 
		$a_03_1 = {8b 45 10 81 38 01 01 00 00 75 13 8b 45 10 81 78 04 10 2a 00 00 75 07 33 c0 a3 90 01 04 8b 45 10 81 38 01 01 00 00 75 13 8b 45 10 81 78 04 11 1d 00 00 75 07 90 00 } //01 00 
		$a_01_2 = {2e 6f 6e 73 75 62 6d 69 74 20 3d 20 76 61 6c 69 64 61 4d 61 6e 64 61 3b } //01 00  .onsubmit = validaManda;
		$a_01_3 = {5b 56 45 52 53 41 4f 5d } //01 00  [VERSAO]
		$a_01_4 = {54 49 64 44 65 63 6f 64 65 72 42 69 6e 48 65 78 34 } //01 00  TIdDecoderBinHex4
		$a_01_5 = {3c 73 65 72 69 61 6c 68 64 3e } //01 00  <serialhd>
		$a_01_6 = {3c 2f 63 6f 6d 70 75 74 65 72 6e 61 6d 65 3e } //01 00  </computername>
		$a_01_7 = {46 72 6d 50 72 69 6e 63 69 70 61 6c } //01 00  FrmPrincipal
		$a_01_8 = {3c 54 45 58 54 4f 41 52 51 55 49 56 4f 3e } //01 00  <TEXTOARQUIVO>
		$a_01_9 = {3c 4e 4f 4d 45 41 52 51 55 49 56 4f 3e } //01 00  <NOMEARQUIVO>
		$a_01_10 = {3c 4d 45 4e 53 41 47 45 4d 3e } //01 00  <MENSAGEM>
		$a_01_11 = {41 56 47 20 45 2d 6d 61 69 6c 20 53 63 61 6e 6e 65 72 } //01 00  AVG E-mail Scanner
		$a_01_12 = {4e 6f 72 74 6f 6e 20 41 6e 74 69 56 69 72 75 73 } //01 00  Norton AntiVirus
		$a_01_13 = {42 72 61 64 65 73 63 6f 20 4e 65 74 20 45 6d 70 72 65 73 61 } //01 00  Bradesco Net Empresa
		$a_01_14 = {45 76 65 6e 74 6f 3a } //01 00  Evento:
		$a_01_15 = {41 72 71 75 69 76 6f 20 43 6f 6e 66 69 67 75 72 61 } //01 00  Arquivo Configura
		$a_01_16 = {64 65 6c 20 2f 71 20 2f 66 20 22 25 73 } //01 00  del /q /f "%s
		$a_01_17 = {6c 69 6e 6b 73 5b 69 5d 2e 6f 6e 63 6c 69 63 6b 2e 74 6f 53 74 72 69 6e 67 28 29 2e 69 6e 64 65 78 4f 66 28 } //01 00  links[i].onclick.toString().indexOf(
		$a_01_18 = {3c 2f 73 65 6e 68 61 3e } //00 00  </senha>
	condition:
		any of ($a_*)
 
}