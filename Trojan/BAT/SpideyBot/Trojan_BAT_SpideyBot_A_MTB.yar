
rule Trojan_BAT_SpideyBot_A_MTB{
	meta:
		description = "Trojan:BAT/SpideyBot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 25 72 90 01 03 70 07 72 90 01 03 70 28 90 01 03 0a 6f 90 01 03 0a 25 72 0e 01 90 00 } //1
		$a_03_1 = {07 08 9a 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 6f 90 01 03 0a 0d 90 00 } //1
		$a_03_2 = {0a 74 19 00 90 01 01 01 13 90 01 01 06 11 90 01 01 6f 90 01 03 0a 6f 90 01 03 0a 09 6f 90 01 03 0a 2d de 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}