
rule Trojan_BAT_FormBook_PAC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {25 16 07 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 } //3
		$a_01_1 = {20 00 46 01 00 0a 03 2c } //1
		$a_01_2 = {20 00 56 01 00 14 14 16 } //1  Ŗ᐀ᘔ
		$a_81_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}