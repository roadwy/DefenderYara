
rule Trojan_Win64_CobaltStrike_JT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 90 01 01 31 01 48 8b 44 24 90 01 01 48 83 c0 90 01 01 48 89 44 24 90 01 01 48 8b 44 24 90 01 01 48 83 c0 90 01 01 48 89 44 24 90 01 01 48 8b 44 24 90 01 01 48 3b c6 48 89 44 24 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}