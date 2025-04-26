
rule Trojan_Win64_CobaltStrike_JT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? 31 01 48 8b 44 24 ?? 48 83 c0 ?? 48 89 44 24 ?? 48 8b 44 24 ?? 48 83 c0 ?? 48 89 44 24 ?? 48 8b 44 24 ?? 48 3b c6 48 89 44 24 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}