
rule TrojanSpy_Win32_Banbra_I{
	meta:
		description = "TrojanSpy:Win32/Banbra.I,SIGNATURE_TYPE_PEHSTR,1b 00 1b 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 65 6e 68 61 74 78 74 00 00 } //0a 00 
		$a_01_1 = {53 65 6e 68 61 4a 75 6a 75 00 00 } //02 00 
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 62 72 61 64 65 73 63 6f 6e 65 74 65 6d 70 72 65 73 61 2e 63 6f 6d 2e 62 72 20 2d 20 20 42 72 61 64 65 73 63 6f 20 2d 20 43 6f 6c 6f 63 61 6e 64 6f 20 76 6f 63 } //02 00  https://bradesconetempresa.com.br -  Bradesco - Colocando voc
		$a_01_3 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 00 00 52 00 65 00 67 00 57 00 72 00 69 00 74 00 65 00 } //02 00 
		$a_01_4 = {4c 00 65 00 69 00 74 00 6f 00 72 00 20 00 53 00 6d 00 61 00 72 00 74 00 43 00 61 00 72 00 64 00 20 00 6e 00 } //01 00  Leitor SmartCard n
		$a_01_5 = {20 73 65 6d 70 72 65 20 61 20 66 72 65 6e 74 65 } //01 00   sempre a frente
		$a_01_6 = {42 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 20 00 4e 00 65 00 74 00 20 00 45 00 6d 00 70 00 72 00 65 00 73 00 61 00 } //00 00  Bradesco Net Empresa
	condition:
		any of ($a_*)
 
}