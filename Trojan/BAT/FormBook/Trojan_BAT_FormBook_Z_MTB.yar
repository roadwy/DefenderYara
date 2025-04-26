
rule Trojan_BAT_FormBook_Z_MTB{
	meta:
		description = "Trojan:BAT/FormBook.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 07 02 8e 69 6a 5d b7 02 07 02 8e 69 6a 5d b7 91 03 07 03 8e 69 6a 5d b7 91 61 02 07 17 6a d6 02 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 00 07 17 6a d6 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}