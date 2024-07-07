
rule Trojan_BAT_FormBook_AAMQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {10 01 0f 01 03 8e 69 18 59 28 90 01 01 00 00 2b 00 d0 90 01 01 00 00 01 28 90 01 01 00 00 0a 72 75 00 00 70 20 00 01 00 00 14 14 17 8d 90 01 01 00 00 01 25 16 02 90 00 } //4
		$a_01_1 = {42 00 75 00 74 00 61 00 } //1 Buta
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}