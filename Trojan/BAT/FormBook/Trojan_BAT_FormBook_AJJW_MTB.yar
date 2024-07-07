
rule Trojan_BAT_FormBook_AJJW_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AJJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 4d 00 11 04 07 8e 69 5d 13 05 07 11 05 91 13 06 08 11 04 1f 16 5d 6f 90 01 03 0a d2 13 07 07 11 04 17 58 07 8e 69 5d 91 13 08 11 06 11 07 61 11 08 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 09 07 11 05 11 09 d2 9c 00 11 04 17 59 13 04 11 04 16 fe 04 16 fe 01 13 0a 11 0a 2d a5 90 00 } //2
		$a_01_1 = {42 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 53 00 79 00 73 00 74 00 65 00 6d 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //1 BankingSystemSimulation
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}