
rule Trojan_BAT_FormBook_ERV_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ERV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 20 ?? ?? ?? ?? 5d 03 02 20 ?? ?? ?? ?? 04 28 ?? ?? ?? 06 03 04 17 58 20 ?? ?? ?? ?? 5d 91 59 06 58 06 5d d2 9c 03 0b 2b 00 } //1
		$a_03_1 = {02 05 04 5d 91 03 05 1f 16 5d 6f ?? ?? ?? 0a 61 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}