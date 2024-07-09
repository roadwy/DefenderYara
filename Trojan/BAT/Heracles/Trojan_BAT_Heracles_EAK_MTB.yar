
rule Trojan_BAT_Heracles_EAK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 14 2b 19 74 ?? 00 00 01 2b 19 74 ?? 00 00 1b 2b 19 2b 1e de 22 28 ?? 03 00 06 2b e5 28 ?? 03 00 06 2b e0 28 ?? 02 00 06 2b e0 28 ?? 03 00 06 2b e0 0a 2b df 26 de bf } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}