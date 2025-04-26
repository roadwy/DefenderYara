
rule Trojan_BAT_FormBook_EWK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 03 05 1f 16 5d 6f ?? ?? ?? 0a 61 13 01 } //1
		$a_03_1 = {03 02 20 00 22 00 00 04 28 ?? ?? ?? 06 03 04 17 58 20 00 22 00 00 5d 91 28 ?? ?? ?? 0a 59 11 03 58 11 03 5d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}