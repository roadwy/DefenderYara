
rule TrojanSpy_Win32_Bancos_AAA{
	meta:
		description = "TrojanSpy:Win32/Bancos.AAA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 65 00 00 00 43 61 6d 70 6f 20 69 6e 76 e1 6c 69 64 6f 21 00 ff ff ff ff } //1
		$a_01_1 = {73 75 63 6c 61 2e 61 72 67 65 6e 74 69 6e 61 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //1 sucla.argentina@hotmail.com
		$a_01_2 = {68 6f 6a 65 31 30 30 33 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //1 hoje1003@hotmail.com
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6f 6c 65 6f 7a 6f 6e 2e 65 75 2f 74 65 6d 70 6c 61 74 65 73 2f 6a 61 5f 70 75 72 69 74 79 2f 6a 73 2f 69 6d 70 6f 72 74 2e 70 68 70 } //1 http://www.oleozon.eu/templates/ja_purity/js/import.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}