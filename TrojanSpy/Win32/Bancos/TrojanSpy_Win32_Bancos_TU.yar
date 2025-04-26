
rule TrojanSpy_Win32_Bancos_TU{
	meta:
		description = "TrojanSpy:Win32/Bancos.TU,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 63 61 64 61 73 74 72 6f 20 2d 20 42 61 6e 63 6f 20 64 6f 20 42 72 61 73 69 6c 2e } //1 Recadastro - Banco do Brasil.
		$a_01_1 = {53 65 6e 68 61 20 64 65 20 38 20 64 69 67 69 74 6f 73 2e 2e 2e 2e 3a 20 } //1 Senha de 8 digitos....: 
		$a_01_2 = {64 75 6c 6f 20 42 34 4e 4b 20 30 46 20 42 52 34 5a 31 4c } //2 dulo B4NK 0F BR4Z1L
		$a_01_3 = {69 6e 63 6f 72 72 65 74 6f 21 20 56 65 72 69 66 69 71 75 65 20 61 20 73 75 61 20 73 65 6e 68 61 20 64 65 20 61 75 74 6f 61 74 65 6e 64 69 6d 65 6e 74 6f 2c 20 71 75 65 20 70 6f 73 73 75 69 20 38 20 28 6f 69 74 6f 29 20 64 } //1 incorreto! Verifique a sua senha de autoatendimento, que possui 8 (oito) d
		$a_01_4 = {73 6d 74 70 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //1 smtp.terra.com.br
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}