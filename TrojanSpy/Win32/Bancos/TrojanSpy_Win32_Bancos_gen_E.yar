
rule TrojanSpy_Win32_Bancos_gen_E{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 45 43 32 40 4f 00 } //10
		$a_00_1 = {53 65 6e 68 61 } //1 Senha
		$a_00_2 = {43 61 72 74 61 6f } //1 Cartao
		$a_00_3 = {41 63 65 73 73 6f } //1 Acesso
		$a_00_4 = {63 61 69 78 61 } //1 caixa
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=14
 
}