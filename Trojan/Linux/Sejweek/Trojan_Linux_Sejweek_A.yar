
rule Trojan_Linux_Sejweek_A{
	meta:
		description = "Trojan:Linux/Sejweek.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 6f 00 64 00 61 00 79 00 2d 00 66 00 72 00 69 00 64 00 61 00 79 00 2e 00 63 00 6e 00 2f 00 6d 00 61 00 72 00 61 00 6e 00 2f 00 73 00 65 00 6a 00 76 00 61 00 6e 00 2f 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00 } //1 http://today-friday.cn/maran/sejvan/get.php
		$a_01_1 = {72 e5 00 00 70 80 0a 00 00 04 20 80 6d ef 04 80 0b 00 00 04 20 80 6d ef 04 80 0c 00 00 04 17 80 10 00 00 04 73 58 00 00 0a 80 12 00 00 04 2a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}