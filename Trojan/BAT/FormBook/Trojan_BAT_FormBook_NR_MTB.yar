
rule Trojan_BAT_FormBook_NR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 6a 61 d2 9c 11 0a 17 6a 58 13 0a 11 0a 11 07 8e 69 17 59 6a 31 88 } //10
		$a_01_1 = {5f d2 13 0c 11 06 11 0c 95 d2 13 0d 11 07 11 0a d4 11 0b 6e } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}