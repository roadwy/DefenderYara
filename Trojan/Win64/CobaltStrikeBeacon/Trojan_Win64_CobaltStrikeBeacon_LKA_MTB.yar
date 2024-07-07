
rule Trojan_Win64_CobaltStrikeBeacon_LKA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeBeacon.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 01 0f b7 04 24 66 ff c8 66 89 04 24 48 8b 44 24 90 01 01 48 83 c0 04 48 89 44 24 38 48 8b 44 24 90 01 01 48 83 c0 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}