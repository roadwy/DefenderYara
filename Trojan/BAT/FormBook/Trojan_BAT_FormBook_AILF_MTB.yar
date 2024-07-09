
rule Trojan_BAT_FormBook_AILF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AILF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 2b 18 07 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 08 17 58 13 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}