
rule Trojan_BAT_Amadey_PABW_MTB{
	meta:
		description = "Trojan:BAT/Amadey.PABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 30 53 ef 67 20 e8 6f 2a ca 59 20 f7 0c 6a 17 61 20 bf ef ae 8a 61 7d 1b 04 00 04 20 41 } //1
		$a_01_1 = {7e 2e 04 00 04 20 f2 06 ef bf 20 02 00 00 00 62 20 03 00 00 00 62 20 40 de e0 fd 61 7d 36 04 00 04 20 11 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}