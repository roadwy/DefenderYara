
rule Trojan_BAT_FormBook_EUJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 03 66 5f 02 66 03 5f 60 ?? ?? ?? ?? ?? 0a 06 2a } //1
		$a_01_1 = {51 00 50 00 56 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 51 00 50 00 56 00 } //1 QPVMethod0QPV
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}