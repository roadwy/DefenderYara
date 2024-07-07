
rule Trojan_BAT_FormBook_CZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {08 07 17 73 90 01 01 00 00 0a 0d 90 00 } //2
		$a_03_1 = {09 02 16 02 8e 69 6f 90 01 01 00 00 0a 00 09 6f 90 00 } //2
		$a_01_2 = {06 0b 07 06 8e 69 1f 40 12 02 28 } //2
		$a_01_3 = {09 11 04 58 06 11 04 91 52 } //2
		$a_01_4 = {11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}