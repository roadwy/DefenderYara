
rule Trojan_BAT_FormBook_I_MTB{
	meta:
		description = "Trojan:BAT/FormBook.I!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 15 00 00 0a 06 16 20 e8 03 00 00 6f 16 00 00 0a 8c 1a 00 00 01 08 17 9a 28 17 00 00 0a 13 04 11 04 09 28 18 00 00 0a 00 11 04 } //1
		$a_01_1 = {11 04 8f 30 00 00 01 25 71 30 00 00 01 09 09 06 e0 95 09 07 e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}