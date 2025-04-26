
rule Trojan_BAT_FormBook_AIFC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AIFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 07 06 28 ?? ?? ?? 06 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 } //2
		$a_01_1 = {48 00 79 00 76 00 65 00 73 00 } //1 Hyves
		$a_01_2 = {43 00 68 00 65 00 61 00 74 00 4d 00 65 00 6e 00 75 00 } //1 CheatMenu
		$a_01_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}