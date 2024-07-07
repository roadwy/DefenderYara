
rule Trojan_BAT_FormBook_MBEX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 08 d4 07 11 08 d4 91 11 06 11 06 09 95 11 06 11 04 95 58 20 ff 00 00 00 5f 95 61 d2 9c 11 08 17 6a 58 13 08 11 08 11 07 8e 69 17 59 6a 31 9f } //1
		$a_01_1 = {74 00 51 00 2e 00 4d 00 49 00 } //1 tQ.MI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}