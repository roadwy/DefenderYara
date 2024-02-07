
rule TrojanSpy_Win32_Banker_VM{
	meta:
		description = "TrojanSpy:Win32/Banker.VM,SIGNATURE_TYPE_PEHSTR,31 01 31 01 1b 00 00 64 00 "
		
	strings :
		$a_01_0 = {3c 69 6e 70 75 74 20 74 79 70 65 3d 68 69 64 64 65 6e 20 6e 61 6d 65 3d 4e 6f 6d 65 55 73 75 61 72 69 6f 20 69 64 3d 4e 6f 6d 65 55 73 75 61 72 69 6f 20 73 69 7a 65 3d 38 3e } //64 00  <input type=hidden name=NomeUsuario id=NomeUsuario size=8>
		$a_01_1 = {3c 69 6e 70 75 74 20 74 79 70 65 3d 68 69 64 64 65 6e 20 6e 61 6d 65 3d 53 65 6e 68 61 55 73 75 61 72 69 6f 20 69 64 3d 53 65 6e 68 61 55 73 75 61 72 69 6f 20 73 69 7a 65 3d 36 3e } //64 00  <input type=hidden name=SenhaUsuario id=SenhaUsuario size=6>
		$a_01_2 = {3c 69 6e 70 75 74 20 74 79 70 65 3d 68 69 64 64 65 6e 20 6e 61 6d 65 3d 74 78 74 41 73 73 42 61 6e 20 69 64 3d 74 78 74 41 73 73 42 61 6e 20 73 69 7a 65 3d 38 3e } //01 00  <input type=hidden name=txtAssBan id=txtAssBan size=8>
		$a_01_3 = {62 61 6e 63 6f 61 6c 66 61 } //01 00  bancoalfa
		$a_01_4 = {62 61 6e 63 6f 62 72 61 73 69 6c } //01 00  bancobrasil
		$a_01_5 = {62 61 6e 63 6f 64 6f 65 73 74 61 64 6f } //01 00  bancodoestado
		$a_01_6 = {62 61 6e 63 6f 66 69 62 72 61 } //01 00  bancofibra
		$a_01_7 = {62 61 6e 63 6f 72 75 72 61 6c } //01 00  bancorural
		$a_01_8 = {62 61 6e 65 73 65 } //01 00  banese
		$a_01_9 = {62 61 6e 65 73 70 61 } //01 00  banespa
		$a_01_10 = {62 61 6e 72 69 73 75 6c } //01 00  banrisul
		$a_01_11 = {62 62 63 6f 6d 62 72 } //01 00  bbcombr
		$a_01_12 = {62 65 73 63 } //01 00  besc
		$a_01_13 = {63 69 74 69 62 61 6e 6b } //01 00  citibank
		$a_01_14 = {63 6f 63 72 65 64 68 6f 6d 65 } //01 00  cocredhome
		$a_01_15 = {69 6e 74 65 72 6e 65 74 62 61 6e 6b 69 6e 67 63 61 69 78 61 } //01 00  internetbankingcaixa
		$a_01_16 = {69 6e 74 65 72 6e 65 74 63 61 69 78 61 2e 63 61 69 78 61 2e 67 6f 76 2e 62 72 } //01 00  internetcaixa.caixa.gov.br
		$a_01_17 = {6e 6f 73 73 61 63 61 69 78 61 } //01 00  nossacaixa
		$a_01_18 = {72 65 61 6c 69 6e 74 65 72 6e 65 74 65 6d 70 72 65 73 61 } //01 00  realinternetempresa
		$a_01_19 = {73 61 6e 74 61 6e 64 65 72 } //01 00  santander
		$a_01_20 = {73 65 63 75 72 65 77 65 62 } //01 00  secureweb
		$a_01_21 = {73 69 63 72 65 64 69 } //01 00  sicredi
		$a_01_22 = {73 6f 66 69 73 61 } //01 00  sofisa
		$a_01_23 = {73 75 64 61 6d 65 72 69 73 } //01 00  sudameris
		$a_01_24 = {74 65 63 6c 61 64 6f 76 69 72 74 75 61 6c } //01 00  tecladovirtual
		$a_01_25 = {74 72 69 62 61 6e 63 6f } //01 00  tribanco
		$a_01_26 = {75 6e 69 62 61 6e 63 6f } //00 00  unibanco
	condition:
		any of ($a_*)
 
}