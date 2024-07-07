
rule TrojanSpy_Win32_Bancos_YB{
	meta:
		description = "TrojanSpy:Win32/Bancos.YB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b7 1a 0f bf 31 0f af de 81 c3 00 08 00 00 8b 74 24 24 c1 fb 0c 83 c1 02 89 1e 83 c2 02 83 44 24 24 04 40 83 f8 40 7c } //1
		$a_00_1 = {73 65 6e 68 61 } //1 senha
		$a_00_2 = {62 61 6e 63 6f } //1 banco
		$a_00_3 = {43 6f 6e 66 69 67 75 72 61 63 61 6f 20 64 65 20 64 65 70 6f 73 69 74 6f } //1 Configuracao de deposito
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}