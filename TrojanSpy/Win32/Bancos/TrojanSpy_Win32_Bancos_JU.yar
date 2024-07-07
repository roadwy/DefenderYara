
rule TrojanSpy_Win32_Bancos_JU{
	meta:
		description = "TrojanSpy:Win32/Bancos.JU,SIGNATURE_TYPE_PEHSTR,17 00 14 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 62 72 61 64 65 73 63 6f 6e 65 74 65 6d 70 72 65 73 61 2e 63 6f 6d 2e 62 72 2f 6e 65 2f 69 6e 69 63 69 61 73 65 73 73 61 6f 2e 61 73 70 } //5 https://bradesconetempresa.com.br/ne/iniciasessao.asp
		$a_01_1 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //5 =_NextPart_2rfkindysadvnqw3nerasdf
		$a_01_2 = {41 20 43 68 61 76 65 20 64 65 20 53 65 67 75 72 61 6e e7 61 20 64 69 67 69 74 61 64 61 20 65 20 69 6e 76 e1 6c 69 64 61 2e } //5
		$a_01_3 = {66 74 70 2e 77 65 62 61 6c 69 63 65 2e 69 74 } //5 ftp.webalice.it
		$a_01_4 = {73 64 65 6d 61 69 61 40 75 6f 6c 2e 63 6f 6d 2e 62 72 } //1 sdemaia@uol.com.br
		$a_01_5 = {76 6f 6c 74 61 67 65 73 6b 38 40 67 6d 61 69 6c 2e 63 6f 6d } //1 voltagesk8@gmail.com
		$a_01_6 = {73 6d 74 70 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 } //1 smtps.uol.com.br
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=20
 
}