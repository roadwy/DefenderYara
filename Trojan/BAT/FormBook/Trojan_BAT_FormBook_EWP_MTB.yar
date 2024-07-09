
rule Trojan_BAT_FormBook_EWP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 ?? ?? ?? ?? ?? 18 58 19 59 } //1
		$a_03_1 = {02 03 04 18 ?? ?? ?? ?? ?? 1f 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}