
rule TrojanSpy_Win32_Bancos_PL{
	meta:
		description = "TrojanSpy:Win32/Bancos.PL,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c 72 66 6b 73 61 64 76 6e 71 69 6e 64 79 77 33 6e 65 72 61 73 64 66 } //1 _NextPart_2relrfksadvnqindyw3nerasdf
		$a_01_1 = {44 49 47 49 54 41 52 20 45 52 52 41 44 4f } //1 DIGITAR ERRADO
		$a_01_2 = {42 52 41 44 45 53 43 4f 20 4e 55 4e 43 41 20 53 4f 4c 49 43 49 54 41 } //1 BRADESCO NUNCA SOLICITA
		$a_01_3 = {63 68 61 76 65 3a } //1 chave:
		$a_01_4 = {45 2d 42 61 6e 6b 69 6e 67 20 69 6e 73 74 61 6c 61 64 6f } //1 E-Banking instalado
		$a_01_5 = {62 74 6e 6c 69 6d 70 61 43 6c 69 63 6b } //1 btnlimpaClick
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}