
rule Trojan_Win64_CobaltStrike_SH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 01 83 90 01 04 49 90 01 03 48 90 01 03 48 90 0a 33 00 8b 4b 90 01 01 35 90 01 04 29 43 90 01 01 33 4b 90 01 01 48 90 01 06 41 90 01 03 b8 90 01 04 0f af 53 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}