
rule TrojanSpy_Win32_Bancos_MY{
	meta:
		description = "TrojanSpy:Win32/Bancos.MY,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 72 63 3d 22 68 74 74 70 73 3a 2f 2f 69 74 61 75 62 61 6e 6b 6c 69 6e 65 2e 69 74 61 75 2e 63 6f 6d 2e 62 72 2f 56 31 2f 50 45 52 53 2f 49 4d 47 2f 62 74 5f 63 6f 6e 66 69 72 6d 61 72 2e 67 69 66 } //01 00  src="https://itaubankline.itau.com.br/V1/PERS/IMG/bt_confirmar.gif
		$a_01_1 = {63 6c 61 73 73 3d 63 6f 72 70 6f 5f 74 65 78 74 6f 5f 64 65 73 74 61 63 61 64 6f } //01 00  class=corpo_texto_destacado
		$a_01_2 = {62 6f 74 61 6f 5f 63 6f 6e 66 69 72 6d 61 72 5f 4f 6e 43 6c 69 63 6b } //01 00  botao_confirmar_OnClick
		$a_01_3 = {69 6d 67 54 65 63 6c 61 64 6f 30 31 5f 4f 6e 43 6c 69 63 6b } //01 00  imgTeclado01_OnClick
		$a_01_4 = {47 62 50 6c 75 67 69 6e 4f 62 6a 2e 44 69 67 65 73 74 28 22 22 29 3b 20 64 6f 63 75 6d 65 6e 74 2e } //01 00  GbPluginObj.Digest(""); document.
		$a_01_5 = {62 6f 74 61 6f 45 6e 74 72 61 72 5f 4f 6e 43 6c 69 63 6b } //02 00  botaoEntrar_OnClick
		$a_01_6 = {49 45 42 72 6f 77 73 65 72 45 76 65 6e 74 73 2e 64 6c 6c } //00 00  IEBrowserEvents.dll
	condition:
		any of ($a_*)
 
}