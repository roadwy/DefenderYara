
rule Trojan_Win64_CobaltStrike_GKN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 89 44 24 38 48 8b 44 24 38 48 8b 40 18 48 89 44 24 40 48 8b 44 24 40 48 83 c0 20 48 89 44 24 30 48 8b 44 24 30 48 8b 00 48 89 44 24 20 48 8b 44 24 30 48 39 44 24 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}