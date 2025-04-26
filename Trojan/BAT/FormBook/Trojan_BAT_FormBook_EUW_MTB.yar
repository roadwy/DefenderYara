
rule Trojan_BAT_FormBook_EUW_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 91 07 61 06 ?? ?? ?? ?? ?? 09 91 61 13 05 1f 0f 13 0a } //1
		$a_01_1 = {02 02 8e 69 17 59 91 1f 70 61 0b 11 0b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}