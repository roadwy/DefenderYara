
rule Trojan_BAT_FormBook_BJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 07 07 11 07 91 11 04 11 0d 95 61 d2 9c 11 0b 11 0e 5a 13 10 11 07 17 58 13 } //4
		$a_01_1 = {44 00 44 00 5a 00 34 00 35 00 53 00 34 00 59 00 57 00 41 00 35 00 37 00 42 00 39 00 44 00 56 00 35 00 47 00 47 00 35 00 37 00 52 00 } //1 DDZ45S4YWA57B9DV5GG57R
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=4
 
}