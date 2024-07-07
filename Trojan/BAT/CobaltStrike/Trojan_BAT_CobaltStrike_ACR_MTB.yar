
rule Trojan_BAT_CobaltStrike_ACR_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 20 00 30 00 00 1f 40 16 28 90 01 01 00 00 06 0a 00 02 25 13 05 2c 06 11 05 8e 69 2d 05 16 e0 0b 2b 09 11 05 16 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}