
rule Trojan_BAT_FormBook_MAAE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MAAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 07 9a 1f 10 7e ?? 00 00 04 28 ?? ?? ?? 06 86 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06 } //1
		$a_03_1 = {72 40 21 04 70 72 44 21 04 70 7e ?? 00 00 04 28 ?? ?? 00 06 72 48 21 04 70 72 4c 21 04 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}