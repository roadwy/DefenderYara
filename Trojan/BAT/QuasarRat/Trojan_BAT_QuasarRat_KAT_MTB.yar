
rule Trojan_BAT_QuasarRat_KAT_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 2e 01 00 0a 13 09 11 09 06 6f 2f 01 00 0a 6f 30 01 00 0a 00 11 09 06 6f 2f 01 00 0a 6f 31 01 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}