
rule Trojan_Win32_Lexer_A{
	meta:
		description = "Trojan:Win32/Lexer.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 33 ff b8 90 01 04 8b 0d 70 76 40 00 8a 0c 39 80 e9 4d 88 08 8a 08 88 0d 90 01 04 8a 0d 90 01 04 80 f1 0b 88 08 47 40 4a 75 90 00 } //1
		$a_03_1 = {68 03 01 00 00 e8 90 01 04 8d 45 ec ba 90 01 04 b9 04 01 00 00 e8 90 01 04 8d 45 ec ba 90 01 04 e8 90 01 04 8b 55 ec 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}