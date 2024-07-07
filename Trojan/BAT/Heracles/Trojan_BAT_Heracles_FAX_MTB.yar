
rule Trojan_BAT_Heracles_FAX_MTB{
	meta:
		description = "Trojan:BAT/Heracles.FAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 2b b1 08 09 07 09 91 06 09 06 8e 69 5d 91 61 d2 9c 09 17 58 0d 20 90 02 04 2b 97 09 07 8e 69 2f 08 90 00 } //2
		$a_03_1 = {25 26 2b 80 11 04 20 90 02 04 5a 20 90 02 04 61 38 90 01 01 ff ff ff 07 8e 69 8d 90 01 01 01 00 01 0c 16 0d 11 04 20 90 02 04 5a 20 90 02 04 61 38 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}