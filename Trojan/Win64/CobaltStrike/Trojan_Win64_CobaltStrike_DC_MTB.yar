
rule Trojan_Win64_CobaltStrike_DC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 04 24 8b 44 24 90 01 01 39 04 24 73 90 01 01 8b 04 24 0f b6 4c 24 90 01 01 48 8b 54 24 90 01 01 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}