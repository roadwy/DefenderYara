
rule Trojan_BAT_FormBook_AAYS_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 5d 13 06 06 11 07 5d 13 0a 07 11 06 91 13 0b 11 04 11 0a 6f ?? 00 00 0a 13 0c 02 07 06 28 ?? ?? 00 06 13 0d 02 11 0b 11 0c 11 0d 28 ?? ?? 00 06 13 0e 07 11 06 11 0e 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 0f 11 0f 2d ad } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}