
rule Trojan_BAT_FormBook_NFK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 74 00 00 0a 28 90 01 02 00 2b 0d 09 1f 10 28 90 01 02 00 2b 09 6f 90 01 02 00 0a 1f 10 59 28 90 01 02 00 2b 73 90 01 02 00 0a 13 04 d0 90 01 02 00 01 28 90 01 02 00 0a 72 90 01 02 00 70 20 90 01 02 00 00 14 14 17 8d 90 01 02 00 01 25 16 11 04 6f 90 01 02 00 0a a2 28 90 01 02 00 0a 74 90 01 02 00 01 90 00 } //5
		$a_01_1 = {58 69 67 47 53 6d 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 XigGSm.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}