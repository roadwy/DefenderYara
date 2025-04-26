
rule Trojan_BAT_FormBook_ARAQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 1f 16 5d 91 61 07 08 17 58 09 5d 91 59 20 00 01 00 00 58 13 04 07 08 11 04 20 ff 00 00 00 5f 28 ?? ?? ?? 0a 9c 08 17 58 0c 08 07 8e 69 32 a0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}