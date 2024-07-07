
rule Trojan_BAT_RevengeRAT_A_MTB{
	meta:
		description = "Trojan:BAT/RevengeRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 14 1a 8d 90 01 01 00 00 01 13 07 11 07 16 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a a2 11 07 17 72 90 01 01 00 00 70 a2 11 07 18 11 01 a2 11 07 19 16 8c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}