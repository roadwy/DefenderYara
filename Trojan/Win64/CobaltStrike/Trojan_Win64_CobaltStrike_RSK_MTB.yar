
rule Trojan_Win64_CobaltStrike_RSK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 89 45 48 48 8b 45 48 48 8b 40 18 48 89 45 68 48 8b 45 68 48 83 c0 20 48 89 85 88 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}