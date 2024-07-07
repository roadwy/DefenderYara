
rule TrojanSpy_Win32_Bancos_gen_D{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd2 00 ffffffd2 00 0f 00 00 "
		
	strings :
		$a_01_0 = {45 6d 62 65 64 64 65 64 20 57 65 62 20 42 72 6f 77 73 65 72 20 66 72 6f 6d 3a } //100 Embedded Web Browser from:
		$a_01_1 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c } //100 boundary="=_NextPart_2rel
		$a_01_2 = {6a 61 76 61 73 63 72 69 70 74 3a 65 6e 76 69 61 72 28 29 } //3 javascript:enviar()
		$a_01_3 = {26 44 49 47 43 54 41 3d } //3 &DIGCTA=
		$a_01_4 = {26 74 78 74 43 6f 6e 74 61 3d } //3 &txtConta=
		$a_01_5 = {65 64 74 5f 63 72 74 69 74 61 30 33 } //1 edt_crtita03
		$a_01_6 = {65 64 74 5f 69 74 61 63 61 72 64 30 32 } //1 edt_itacard02
		$a_01_7 = {30 31 4b 65 79 50 72 65 73 73 } //1 01KeyPress
		$a_01_8 = {55 6e 69 74 54 65 63 61 64 69 6e 68 6f } //1 UnitTecadinho
		$a_01_9 = {43 6f 6e 74 61 6e 74 6f } //1 Contanto
		$a_01_10 = {52 65 6c 61 74 72 69 6f 64 65 50 72 69 76 61 63 69 64 61 64 65 } //1 RelatriodePrivacidade
		$a_01_11 = {69 6d 67 5f 6c 69 6d 70 61 63 61 72 74 } //1 img_limpacart
		$a_01_12 = {69 6d 67 5f 63 6f 6e 66 69 72 6d 61 63 61 72 74 } //1 img_confirmacart
		$a_01_13 = {50 61 6e 65 6c 43 69 74 69 } //1 PanelCiti
		$a_01_14 = {57 69 6e 64 6f 77 73 6d 65 73 73 65 6e 67 65 72 } //1 Windowsmessenger
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=210
 
}