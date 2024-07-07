
rule Trojan_BAT_CobaltStrike_CXIQ_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.CXIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 08 8f 90 01 04 25 47 11 07 16 91 61 d2 52 00 11 08 17 58 13 08 11 08 11 06 8e 69 fe 04 13 09 11 09 2d d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}