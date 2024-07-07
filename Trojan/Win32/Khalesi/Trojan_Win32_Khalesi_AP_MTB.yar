
rule Trojan_Win32_Khalesi_AP_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {93 54 d0 1e 6c b8 8f 84 6d c8 01 82 73 07 0c c5 43 8a a7 d6 ae 04 0c 01 ee 33 aa 2d b2 7f 2e 6c c8 a5 e6 28 24 d8 54 96 d1 29 b8 ce 4e b5 b8 09 08 fd b8 7e 38 db b1 01 17 54 75 } //1
		$a_01_1 = {0e 48 0b 76 af 8a 32 c9 21 fa 47 30 9c f1 3c 72 c2 2f e7 d3 96 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}