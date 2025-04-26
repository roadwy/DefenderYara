
rule TrojanSpy_Win32_Bancos_PH{
	meta:
		description = "TrojanSpy:Win32/Bancos.PH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f } //1 Arquivos de programas\Internet Explorer\iexplore.exe http://
		$a_03_1 = {20 20 63 61 69 78 61 2e 63 6f 6d 2e 62 72 [0-25] 90 10 03 00 2e 90 10 03 00 2e 90 10 03 00 2e 90 10 03 00 20 20 77 77 77 2e 63 65 66 2e 63 6f 6d 2e 62 72 [0-25] 90 1b 01 2e 90 1b 02 2e 90 1b 03 2e 90 1b 04 } //1
		$a_01_2 = {47 70 66 53 4c 71 62 45 48 34 7a 4e 4b 72 6e 70 55 4e 44 71 50 4d 71 70 43 62 6e 61 53 63 62 73 50 4e 39 70 4e 36 4c 71 4f 72 6e 65 52 74 44 71 53 6d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}