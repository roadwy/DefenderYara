
rule Trojan_BAT_NjRat_NEAE_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 9a 0b 06 07 18 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 08 17 d6 0c 00 08 09 8e b7 fe 04 13 04 11 04 2d d3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}