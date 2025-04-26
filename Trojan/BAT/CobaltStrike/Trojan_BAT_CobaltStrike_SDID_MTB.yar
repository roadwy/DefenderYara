
rule Trojan_BAT_CobaltStrike_SDID_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.SDID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 08 a2 25 17 09 8c 11 00 00 01 a2 11 0e 28 ?? 00 00 2b 26 09 11 0e 8e 69 58 0d 14 13 0c 11 08 17 58 13 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}