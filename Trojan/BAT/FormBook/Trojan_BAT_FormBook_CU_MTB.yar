
rule Trojan_BAT_FormBook_CU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 17 59 91 1f ?? 61 18 } //4
		$a_01_1 = {02 8e 69 17 59 fe 02 16 fe 01 } //2
		$a_01_2 = {61 06 09 91 16 } //2
		$a_01_3 = {02 8e 69 17 58 8d } //2
		$a_01_4 = {02 8e 69 17 59 28 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=12
 
}