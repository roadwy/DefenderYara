
rule Trojan_BAT_FormBook_MBWD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 1f 09 91 1f 16 59 0b } //2
		$a_01_1 = {64 66 67 66 64 66 67 64 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 dfgfdfgd.Form1.resources
		$a_01_2 = {65 33 30 37 37 38 66 37 39 38 61 33 } //1 e30778f798a3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_FormBook_MBWD_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 11 05 6f ?? 00 00 06 11 04 09 6f 45 00 00 06 6f 22 00 00 06 02 7b 01 00 00 04 11 05 11 04 } //2
		$a_01_1 = {53 6b 79 72 69 6d 43 68 61 72 61 63 74 65 72 50 61 72 73 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 SkyrimCharacterParser.Properties
		$a_01_2 = {39 61 64 35 62 32 30 31 61 65 33 37 } //1 9ad5b201ae37
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}