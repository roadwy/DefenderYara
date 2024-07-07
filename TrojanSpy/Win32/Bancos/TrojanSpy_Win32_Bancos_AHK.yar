
rule TrojanSpy_Win32_Bancos_AHK{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 65 63 6c 61 64 6f 20 76 69 72 74 75 61 6c 20 64 65 73 61 62 69 6c 69 74 61 64 6f 2c 20 70 6f 72 20 66 61 76 6f 72 20 75 74 69 6c 69 7a 65 20 73 65 75 20 74 65 63 6c 61 64 6f 20 63 6f 6e 76 65 6e 63 69 6f 6e 61 6c } //1 Teclado virtual desabilitado, por favor utilize seu teclado convencional
		$a_00_1 = {50 72 65 65 6e 63 68 61 20 63 6f 72 72 65 74 61 6d 65 6e 74 65 20 6f 73 20 63 61 6d 70 6f 73 20 73 6f 6c 69 63 69 74 61 64 6f 73 } //1 Preencha corretamente os campos solicitados
		$a_00_2 = {42 61 6e 63 6f 20 53 61 6e 74 61 6e 64 65 72 20 45 6d 70 72 65 73 61 72 69 61 6c } //1 Banco Santander Empresarial
		$a_01_3 = {00 54 6f 6b 20 2f 20 41 73 73 00 } //1
		$a_01_4 = {40 68 6f 74 6d 61 69 6c 2e 63 6f 6d 00 } //1
		$a_02_5 = {35 ae ca 7b c3 ff 25 90 01 04 8b c0 53 33 db 6a 00 e8 90 01 04 83 f8 07 75 1c 6a 01 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}