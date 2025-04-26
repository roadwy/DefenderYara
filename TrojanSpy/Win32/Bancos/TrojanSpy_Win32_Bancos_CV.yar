
rule TrojanSpy_Win32_Bancos_CV{
	meta:
		description = "TrojanSpy:Win32/Bancos.CV,SIGNATURE_TYPE_PEHSTR,20 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 62 6f 72 6c 61 6e 64 5c 64 65 6c 70 68 69 5c 72 74 6c } //10 software\borland\delphi\rtl
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 62 00 61 00 6e 00 6b 00 6c 00 69 00 6e 00 65 00 2e 00 69 00 74 00 61 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 47 00 52 00 49 00 50 00 4e 00 45 00 54 00 2f 00 62 00 6b 00 6c 00 63 00 67 00 69 00 2e 00 65 00 78 00 65 00 } //10 https://bankline.itau.com.br/GRIPNET/bklcgi.exe
		$a_01_2 = {45 6d 62 65 64 64 65 64 57 42 20 68 74 74 70 3a 2f 2f 62 73 61 6c 73 61 2e } //10 EmbeddedWB http://bsalsa.
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 32 00 2e 00 62 00 61 00 6e 00 63 00 6f 00 62 00 72 00 61 00 73 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 61 00 61 00 70 00 66 00 2f 00 6c 00 6f 00 67 00 69 00 6e 00 2e 00 6a 00 73 00 70 00 } //1 https://www2.bancobrasil.com.br/aapf/login.jsp
		$a_01_4 = {52 43 50 54 20 54 4f 3a 3c } //1 RCPT TO:<
		$a_01_5 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c } //1 MAIL FROM:<
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=23
 
}