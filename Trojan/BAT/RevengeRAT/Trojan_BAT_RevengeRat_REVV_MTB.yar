
rule Trojan_BAT_RevengeRat_REVV_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.REVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 91 13 05 00 07 06 11 05 20 78 0a e3 05 58 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 09 8e 69 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}