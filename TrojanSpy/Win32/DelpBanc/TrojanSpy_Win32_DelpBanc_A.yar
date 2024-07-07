
rule TrojanSpy_Win32_DelpBanc_A{
	meta:
		description = "TrojanSpy:Win32/DelpBanc.A,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 09 00 00 "
		
	strings :
		$a_01_0 = {72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //3 rfkindysadvnqw3nerasdf
		$a_01_1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 61 6c 74 65 72 6e 61 74 69 76 65 3b } //1 Content-Type: multipart/alternative;
		$a_01_2 = {70 72 69 6d 65 69 72 61 5f 73 65 72 69 65 } //1 primeira_serie
		$a_01_3 = {73 65 67 75 6e 64 61 5f 73 65 72 69 65 } //1 segunda_serie
		$a_01_4 = {74 65 72 63 65 69 72 61 5f 73 65 72 69 65 } //1 terceira_serie
		$a_01_5 = {71 75 61 72 74 61 5f 73 65 72 69 65 } //1 quarta_serie
		$a_01_6 = {50 6f 72 74 61 6c 20 42 61 6e 63 6f 20 52 65 61 6c } //3 Portal Banco Real
		$a_01_7 = {73 65 6e 68 61 63 61 72 74 61 6f } //3 senhacartao
		$a_01_8 = {41 64 6f 62 65 20 50 68 6f 74 6f 73 68 6f 70 20 37 2e } //2 Adobe Photoshop 7.
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*2) >=14
 
}