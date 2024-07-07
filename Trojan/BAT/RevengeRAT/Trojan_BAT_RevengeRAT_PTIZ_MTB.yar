
rule Trojan_BAT_RevengeRAT_PTIZ_MTB{
	meta:
		description = "Trojan:BAT/RevengeRAT.PTIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 1a 00 00 04 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 04 00 06 80 19 00 00 04 7e 19 00 00 04 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}