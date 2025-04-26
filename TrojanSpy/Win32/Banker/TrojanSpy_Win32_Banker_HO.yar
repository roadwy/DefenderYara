
rule TrojanSpy_Win32_Banker_HO{
	meta:
		description = "TrojanSpy:Win32/Banker.HO,SIGNATURE_TYPE_PEHSTR,1d 00 1a 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 00 77 00 77 00 2e 00 62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 65 00 6d 00 70 00 72 00 65 00 73 00 61 00 73 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //5 www.bradescoempresas.com.br
		$a_01_1 = {77 00 77 00 77 00 2e 00 63 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 65 00 62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //5 www.corporatebradesco.com.br
		$a_01_2 = {42 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 20 00 4e 00 65 00 74 00 20 00 45 00 6d 00 70 00 72 00 65 00 73 00 61 00 } //5 Bradesco Net Empresa
		$a_01_3 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //5 =_NextPart_2rfkindysadvnqw3nerasdf
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 79 70 65 64 55 52 4c 73 } //5 Software\Microsoft\Internet Explorer\TypedURLs
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 79 70 65 64 41 64 64 72 65 73 73 } //5 Software\Microsoft\Internet Explorer\TypedAddress
		$a_01_6 = {00 2e 63 6f 6d } //1
		$a_01_7 = {00 2e 62 61 74 } //1
		$a_01_8 = {00 2e 70 69 66 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=26
 
}