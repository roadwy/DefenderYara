
rule Trojan_BAT_CobaltStrike_ACO_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ACO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 06 16 09 06 8e 69 28 13 00 00 0a 00 09 16 16 28 03 00 00 06 13 04 11 04 08 7e 12 00 00 0a 28 04 00 00 06 00 08 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}