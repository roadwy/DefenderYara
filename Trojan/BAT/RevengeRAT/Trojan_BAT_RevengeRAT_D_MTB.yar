
rule Trojan_BAT_RevengeRAT_D_MTB{
	meta:
		description = "Trojan:BAT/RevengeRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 09 74 ?? 00 00 01 a2 25 13 07 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}