
rule TrojanSpy_Win32_Bancos_DW{
	meta:
		description = "TrojanSpy:Win32/Bancos.DW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c } //1 boundary="=_NextPart_2rel
		$a_01_1 = {73 6d 74 70 2e 69 73 62 74 2e 63 6f 6d 2e 62 72 } //1 smtp.isbt.com.br
		$a_01_2 = {42 72 61 73 64 65 73 63 6f } //1 Brasdesco
		$a_00_3 = {73 65 6e 68 61 } //1 senha
		$a_00_4 = {41 67 75 61 72 64 65 2e 2e } //1 Aguarde..
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}