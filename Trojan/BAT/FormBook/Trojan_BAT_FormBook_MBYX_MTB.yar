
rule Trojan_BAT_FormBook_MBYX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 d6 01 00 70 72 da 01 00 70 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 32 2e 50 72 6f 70 65 72 74 69 65 73 } //3 WindowsFormsApp2.Properties
		$a_01_2 = {36 30 61 38 30 36 34 66 37 64 33 66 } //2 60a8064f7d3f
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}