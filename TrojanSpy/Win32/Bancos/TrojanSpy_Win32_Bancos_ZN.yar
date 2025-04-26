
rule TrojanSpy_Win32_Bancos_ZN{
	meta:
		description = "TrojanSpy:Win32/Bancos.ZN,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 20 65 6e 63 6f 6e 74 72 61 2d 73 65 20 64 65 73 73 69 6e 63 72 6f 6e 69 7a 61 64 6f 2c 20 70 61 72 61 20 73 69 6e 63 72 6f 6e 69 7a 61 72 } //2 a encontra-se dessincronizado, para sincronizar
		$a_01_1 = {64 69 67 6f 20 71 75 65 20 61 70 61 72 65 63 65 20 65 6d 20 73 65 75 20 76 69 73 6f 72 20 64 6f 20 73 65 75 20 69 54 6f 6b 65 6e } //3 digo que aparece em seu visor do seu iToken
		$a_01_2 = {ca dd 27 22 d0 03 fc 1d 2f 4b f4 71 c7 ff ba c7 3f 24 f8 af 7c 18 cc a0 06 37 c8 c1 0e 7a 50 53 } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4) >=9
 
}