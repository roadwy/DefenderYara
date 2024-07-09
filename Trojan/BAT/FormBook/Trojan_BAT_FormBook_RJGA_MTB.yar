
rule Trojan_BAT_FormBook_RJGA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RJGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 06 07 6f ?? ?? ?? 0a 26 08 06 07 6f ?? ?? ?? 0a 13 05 11 05 28 ?? ?? ?? 0a 13 06 11 04 09 11 06 d2 9c 07 17 58 0b 07 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d ca } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}