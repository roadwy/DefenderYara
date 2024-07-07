
rule TrojanSpy_Win32_Bancos_JO{
	meta:
		description = "TrojanSpy:Win32/Bancos.JO,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 00 66 00 66 00 69 00 63 00 65 00 5f 00 61 00 70 00 70 00 00 00 00 00 02 00 00 00 5c 00 00 00 18 00 00 00 68 00 77 00 6d 00 67 00 77 00 6d 00 31 00 32 00 2e 00 65 00 78 00 65 00 } //1
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 69 00 74 00 61 00 75 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 http://www.itau.com.br
		$a_01_2 = {6e 6f 76 61 76 69 62 65 30 31 40 67 6d 61 69 6c 2e 63 6f 6d } //1 novavibe01@gmail.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}