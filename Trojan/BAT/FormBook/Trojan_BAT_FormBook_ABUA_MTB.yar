
rule Trojan_BAT_FormBook_ABUA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1d 11 1f 18 6f ?? 00 00 0a 20 03 02 00 00 28 ?? 00 00 0a 13 21 11 1e 11 21 6f ?? 00 00 0a 00 11 1f 18 58 13 1f 00 11 1f 11 1d 6f ?? 00 00 0a fe 04 13 22 11 22 2d c7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}