
rule Trojan_Win32_Zlader_A{
	meta:
		description = "Trojan:Win32/Zlader.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {2d 9b ff 87 ff ab 35 15 00 14 00 ab 05 ff ff 05 00 ab 83 f0 0a ab 2d 37 00 0d 00 } //1
		$a_01_1 = {2d ad ff 90 ff ab 35 35 00 1b 00 ab 05 11 00 ed ff ab 35 05 00 04 00 ab 2d 16 00 18 00 } //1
		$a_01_2 = {2d 8e ff 8a ff ab 35 1c 00 14 00 ab 05 05 00 9f ff } //1
		$a_01_3 = {2d 89 ff 92 ff ab 35 1e 00 0e 00 ab 05 97 ff 14 56 } //1
		$a_01_4 = {2d 73 00 e7 a9 ab 8b 7d fc 66 c7 47 28 22 00 66 c7 47 2a 25 00 } //1
		$a_01_5 = {58 ff d0 83 e8 04 81 3c 38 2e 65 78 65 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}