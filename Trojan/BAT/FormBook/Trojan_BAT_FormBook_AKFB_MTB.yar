
rule Trojan_BAT_FormBook_AKFB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 17 12 16 28 ?? 01 00 0a 13 18 12 16 28 ?? 01 00 0a 13 19 11 17 11 18 58 11 19 58 26 04 03 6f ?? 01 00 0a 59 25 17 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}