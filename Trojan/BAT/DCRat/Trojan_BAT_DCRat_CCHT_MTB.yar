
rule Trojan_BAT_DCRat_CCHT_MTB{
	meta:
		description = "Trojan:BAT/DCRat.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 1a 72 90 01 04 a2 25 1b 28 90 01 01 00 00 06 a2 25 1c 72 90 01 04 a2 25 1d 28 90 01 01 00 00 06 a2 25 1e 28 90 01 01 00 00 06 a2 28 90 01 01 00 00 0a 7d 90 01 04 16 06 7b 90 01 04 8e 69 28 90 01 01 00 00 0a 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}