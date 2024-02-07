
rule TrojanSpy_Win32_Banker_ZG{
	meta:
		description = "TrojanSpy:Win32/Banker.ZG,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 5c 78 fe 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 eb 03 2b 5d e8 } //01 00 
		$a_01_1 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 69 00 6e 00 6e 00 69 00 6d 00 61 00 74 00 65 00 73 00 } //00 00  \drivers\innimates
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banker_ZG_2{
	meta:
		description = "TrojanSpy:Win32/Banker.ZG,SIGNATURE_TYPE_PEHSTR,04 00 04 00 0c 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 00 6d 00 74 00 70 00 61 00 75 00 74 00 68 00 65 00 6e 00 74 00 69 00 63 00 61 00 74 00 65 00 } //01 00  smtpauthenticate
		$a_01_1 = {62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00  bradesco.com.br
		$a_01_2 = {63 00 61 00 69 00 78 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 } //01 00  caixa.com.b
		$a_01_3 = {72 00 65 00 61 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00  real.com.br
		$a_01_4 = {77 00 77 00 77 00 2e 00 75 00 6e 00 69 00 62 00 61 00 6e 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00  www.unibanco.com.br
		$a_01_5 = {69 00 74 00 61 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00  itau.com.br
		$a_01_6 = {6f 00 72 00 6b 00 75 00 74 00 2e 00 63 00 6f 00 6d 00 } //01 00  orkut.com
		$a_01_7 = {68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00  hotmail.com
		$a_01_8 = {79 00 6f 00 75 00 74 00 75 00 62 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 61 00 74 00 63 00 68 00 } //01 00  youtube.com/watch
		$a_01_9 = {42 61 69 78 61 72 41 72 71 75 69 76 6f 73 } //01 00  BaixarArquivos
		$a_01_10 = {4d 6f 6e 69 74 6f 72 61 45 6e 76 69 6f 44 65 44 61 64 6f 73 } //01 00  MonitoraEnvioDeDados
		$a_01_11 = {74 78 74 53 65 6e 68 61 46 74 70 } //00 00  txtSenhaFtp
	condition:
		any of ($a_*)
 
}