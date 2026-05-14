
rule Trojan_BAT_FormBook_PAB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 16 07 7e 64 00 00 04 25 2d 17 26 7e 63 00 00 04 } //3
		$a_01_1 = {20 00 98 00 00 0a 72 b5 } //1
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}