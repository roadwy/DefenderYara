
rule Trojan_BAT_FormBook_ACH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 07 0e 06 23 00 00 00 00 00 00 ?? ?? 19 28 ?? 00 00 06 0c 02 05 07 6f ?? 00 00 0a 0d 03 04 09 08 06 05 07 } //3
		$a_03_1 = {0a 0f 02 28 ?? 00 00 0a 0b 0f 02 28 ?? 00 00 0a 0c 06 07 08 05 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}