
rule TrojanSpy_Win32_Delf_CG{
	meta:
		description = "TrojanSpy:Win32/Delf.CG,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6d 61 67 65 32 43 6c 69 63 6b } //1 Image2Click
		$a_01_1 = {6f 20 64 6f 20 70 68 70 20 67 6f 6f 67 6c 65 20 67 6d 61 69 6c 20 71 65 20 74 61 20 6c 61 20 6e 61 20 70 61 73 74 61 20 64 65 20 68 6f 73 70 65 64 61 67 65 6d } //2 o do php google gmail qe ta la na pasta de hospedagem
		$a_01_2 = {65 6d 61 69 6c 4b 65 79 44 6f 77 6e } //2 emailKeyDown
		$a_01_3 = {47 6d 61 69 6c 3a 20 45 6d 61 69 6c 20 64 6f 20 47 6f 6f 67 6c 65 20 2d 20 57 69 6e 64 6f 77 73 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //2 Gmail: Email do Google - Windows Internet Explorer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}