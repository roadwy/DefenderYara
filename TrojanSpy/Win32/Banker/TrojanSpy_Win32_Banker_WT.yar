
rule TrojanSpy_Win32_Banker_WT{
	meta:
		description = "TrojanSpy:Win32/Banker.WT,SIGNATURE_TYPE_PEHSTR,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //10 Software\Borland\Delphi
		$a_01_1 = {6d 65 6d 6f 5f 72 65 63 61 64 6f } //1 memo_recado
		$a_01_2 = {70 72 61 71 75 65 6d 3d } //1 praquem=
		$a_01_3 = {74 69 74 75 6c 6f 3d 49 4e 46 45 43 54 41 44 4f 3a 20 } //1 titulo=INFECTADO: 
		$a_01_4 = {74 65 78 74 6f 3d } //1 texto=
		$a_01_5 = {74 69 74 75 6c 6f 3d 50 68 69 73 68 69 6e 67 3a 20 } //1 titulo=Phishing: 
		$a_01_6 = {52 65 63 61 64 61 73 74 72 61 6d 65 6e 74 6f 20 2d 20 43 61 69 78 61 } //1 Recadastramento - Caixa
		$a_01_7 = {53 65 6e 68 61 20 64 6f 20 43 61 72 74 61 6f 2e 2e 2e 2e 2e 2e 3a 20 } //1 Senha do Cartao......: 
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}