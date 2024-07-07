
rule Trojan_BAT_FormBook_GI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {17 2d 06 d0 90 01 03 06 26 72 5b 00 00 70 0a 06 28 90 01 03 0a 25 26 0b 28 90 01 03 0a 25 26 07 16 07 8e 69 6f 90 01 03 0a 0a 28 90 01 03 0a 25 26 06 6f 90 01 03 0a 25 26 0c 1f 61 6a 08 90 00 } //10
		$a_80_1 = {54 6b 4a 57 57 45 4e 4e 56 6c 68 44 53 6b 74 45 4a 51 3d 3d } //TkJWWENNVlhDSktEJQ==  1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}