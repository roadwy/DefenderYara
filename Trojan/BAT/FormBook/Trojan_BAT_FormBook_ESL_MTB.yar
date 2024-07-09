
rule Trojan_BAT_FormBook_ESL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ESL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 02 20 00 22 00 00 04 ?? ?? ?? ?? ?? 03 04 17 58 20 00 22 00 00 5d 91 ?? ?? ?? ?? ?? 59 11 03 58 11 03 5d 13 01 } //1
		$a_03_1 = {02 05 04 5d 91 13 00 ?? ?? ?? ?? ?? 11 00 03 05 1f 16 5d ?? ?? ?? ?? ?? 61 13 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}