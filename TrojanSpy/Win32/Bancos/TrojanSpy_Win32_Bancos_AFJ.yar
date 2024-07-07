
rule TrojanSpy_Win32_Bancos_AFJ{
	meta:
		description = "TrojanSpy:Win32/Bancos.AFJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 61 00 6e 00 74 00 61 00 20 00 70 00 68 00 69 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 santa phi\Project1.vbp
		$a_01_1 = {69 00 6d 00 67 00 2f 00 72 00 6f 00 6c 00 2e 00 67 00 69 00 66 00 } //1 img/rol.gif
		$a_01_2 = {42 61 6e 63 6f 20 53 61 6e 74 61 6e 64 65 72 20 42 72 61 73 69 6c 20 7c 20 42 61 6e 63 6f 20 64 6f 20 6a 75 6e 74 6f 73 } //1 Banco Santander Brasil | Banco do juntos
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}