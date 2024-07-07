
rule Trojan_BAT_FormBook_ATU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ATU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 3c 00 07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f 90 01 03 0a 61 07 11 05 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d b6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_ATU_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ATU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 11 07 8c 46 00 00 01 a2 28 90 01 03 0a a5 19 00 00 01 13 08 12 08 28 90 01 03 0a 13 09 07 11 09 6f 90 01 03 0a 00 00 11 05 17 58 13 05 11 05 08 90 00 } //2
		$a_01_1 = {43 00 72 00 6f 00 73 00 73 00 68 00 61 00 69 00 72 00 4e 00 65 00 74 00 } //1 CrosshairNet
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}