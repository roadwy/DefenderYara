
rule Trojan_Win64_CobaltStrike_KG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 85 ec fe ff ff eb 90 01 01 8b 85 90 01 04 48 63 c0 48 8d 0d 0a 1f 10 00 48 01 c1 8b 85 90 01 04 48 63 c0 48 c1 e0 02 48 8d 15 cb 0e 00 00 48 01 c2 0f b6 02 88 01 eb bb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}