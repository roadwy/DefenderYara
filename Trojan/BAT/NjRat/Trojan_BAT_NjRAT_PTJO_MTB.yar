
rule Trojan_BAT_NjRAT_PTJO_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PTJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 02 00 00 04 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 13 05 28 90 01 01 00 00 0a 11 05 6f 1a 00 00 0a 13 06 11 06 28 90 01 01 00 00 0a 13 07 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}