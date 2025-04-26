
rule Trojan_BAT_FormBook_AWDA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AWDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 0b 07 11 0b 91 11 04 11 0f 95 61 d2 9c 11 11 11 0d 5a 11 0b 58 20 00 01 00 00 5d 13 12 11 0c 11 12 61 13 0c 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 15 11 15 } //4
		$a_01_1 = {50 00 38 00 34 00 38 00 47 00 4f 00 50 00 45 00 47 00 59 00 38 00 5a 00 34 00 48 00 45 00 5a 00 37 00 43 00 35 00 34 00 43 00 47 00 } //1 P848GOPEGY8Z4HEZ7C54CG
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}