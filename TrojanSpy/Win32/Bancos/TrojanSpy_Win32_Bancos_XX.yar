
rule TrojanSpy_Win32_Bancos_XX{
	meta:
		description = "TrojanSpy:Win32/Bancos.XX,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 55 53 42 2e 65 78 65 } //2 :\Arquivos de programas\USB.exe
		$a_01_1 = {3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 73 65 63 64 65 6d 6f 2e 65 78 65 } //2 :\Arquivos de programas\secdemo.exe
		$a_01_2 = {2e 63 6f 6d 2e 62 72 2f 61 63 72 6f 62 61 74 2f 61 63 72 6f 62 61 74 75 33 32 2e 62 6d 70 } //2 .com.br/acrobat/acrobatu32.bmp
		$a_01_3 = {72 65 67 69 73 74 65 72 20 79 6f 75 72 20 63 6f 70 79 20 61 74 } //1 register your copy at
		$a_01_4 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_01_5 = {73 73 6c 65 61 79 33 32 2e 64 6c 6c } //1 ssleay32.dll
		$a_01_6 = {6c 69 62 65 61 79 33 32 2e 64 6c 6c } //1 libeay32.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}