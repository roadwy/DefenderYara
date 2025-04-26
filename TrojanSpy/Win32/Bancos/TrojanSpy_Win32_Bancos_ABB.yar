
rule TrojanSpy_Win32_Bancos_ABB{
	meta:
		description = "TrojanSpy:Win32/Bancos.ABB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 50 72 6f 67 72 61 6d 61 73 5c 47 62 70 6c 75 67 69 6e } //1 C:\Arquivos de Programas\Gbplugin
		$a_03_1 = {70 72 61 71 75 65 6d 3d [0-20] 40 (68 6f 74 6d 61 69 6c 2e 63 6f 6d|67 6d 61 69 6c 2e 63 6f 6d) } //1
		$a_01_2 = {53 65 6e 68 61 20 69 6e 74 65 72 6e 65 74 3a } //1 Senha internet:
		$a_01_3 = {41 72 6d 61 7a 65 6e 61 } //1 Armazena
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}