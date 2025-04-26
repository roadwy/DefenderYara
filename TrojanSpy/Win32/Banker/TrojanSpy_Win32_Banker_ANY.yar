
rule TrojanSpy_Win32_Banker_ANY{
	meta:
		description = "TrojanSpy:Win32/Banker.ANY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 22 45 26 78 63 6c 75 69 72 20 61 72 71 75 69 76 6f 73 20 6f 72 69 67 69 6e 61 69 73 22 } //1 ="E&xcluir arquivos originais"
		$a_01_1 = {3d 22 26 54 69 70 6f 73 20 64 65 20 61 72 71 75 69 76 6f 22 } //1 ="&Tipos de arquivo"
		$a_01_2 = {3d 22 48 6f 6d 65 70 61 67 65 20 64 61 20 4c 61 79 6f 75 74 20 64 6f 20 42 72 61 73 69 6c 22 } //1 ="Homepage da Layout do Brasil"
		$a_01_3 = {63 25 25 77 69 6e 64 6f 77 73 25 73 79 73 74 65 6d 00 } //1 ╣眥湩潤獷猥獹整m
		$a_01_4 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 73 6d 73 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}