
rule TrojanSpy_Win32_Bancos_TS{
	meta:
		description = "TrojanSpy:Win32/Bancos.TS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 61 72 61 20 6c 69 62 65 72 61 72 20 6f 20 41 63 65 73 73 6f 20 73 65 67 75 72 6f 2c 20 43 6f 6e 66 69 72 6d 65 20 73 } //1 Para liberar o Acesso seguro, Confirme s
		$a_01_1 = {53 65 6e 68 61 20 64 65 20 41 75 74 6f 2d 41 74 65 6e 64 69 6d 65 6e 74 6f 3a 20 43 6f 6e 74 65 } //1 Senha de Auto-Atendimento: Conte
		$a_01_2 = {61 20 2d 20 42 61 6e 63 6f 20 64 6f 20 42 72 61 73 69 6c 20 53 2f 41 } //1 a - Banco do Brasil S/A
		$a_00_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 32 00 2e 00 62 00 61 00 6e 00 63 00 6f 00 62 00 72 00 61 00 73 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 61 00 61 00 70 00 66 00 2f 00 6c 00 6f 00 67 00 69 00 6e 00 2e 00 6a 00 73 00 70 00 } //1 https://www2.bancobrasil.com.br/aapf/login.jsp
		$a_01_4 = {7c 42 42 2d 20 43 63 2e 3a } //2 |BB- Cc.:
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*2) >=6
 
}