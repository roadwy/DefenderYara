
rule Trojan_Win64_Ursnif_ZA_MTB{
	meta:
		description = "Trojan:Win64/Ursnif.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ca d3 c7 8b ce 33 fe d3 c3 33 da 8b d5 8b cb 8b ef 8b 7c 24 90 01 01 2b 78 90 01 01 8b da 2b 58 90 01 01 8d 54 09 90 01 01 0f af d1 8d 74 2d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}