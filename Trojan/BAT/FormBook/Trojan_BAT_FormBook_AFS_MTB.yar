
rule Trojan_BAT_FormBook_AFS_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 05 2b 1a 00 09 11 05 08 11 05 91 07 11 05 07 8e 69 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d9 } //2
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 2e 00 49 00 4d 00 45 00 48 00 65 00 6c 00 70 00 65 00 72 00 } //1 WindowsForms.IMEHelper
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_AFS_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 3f 00 16 13 04 2b 24 00 08 09 11 04 6f ?? ?? ?? 0a 13 0b 07 11 05 12 0b 28 ?? ?? ?? 0a 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 0c 11 0c 2d cc } //2
		$a_01_1 = {50 00 6f 00 69 00 6e 00 74 00 5f 00 4f 00 66 00 5f 00 53 00 61 00 6c 00 65 00 } //1 Point_Of_Sale
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}