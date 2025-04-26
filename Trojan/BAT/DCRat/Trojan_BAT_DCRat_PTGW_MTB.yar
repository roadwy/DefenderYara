
rule Trojan_BAT_DCRat_PTGW_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PTGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 1d 00 00 0a 17 59 28 ?? 01 00 0a 16 7e a5 08 00 04 02 1a 28 ?? 01 00 0a 11 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}