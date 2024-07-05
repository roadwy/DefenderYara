
rule Trojan_Win64_CobaltStrike_IG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 c3 39 f7 7e 90 01 01 48 89 f0 83 e0 90 01 01 45 8a 2c 04 44 32 6c 35 90 01 01 ff 15 90 01 04 44 88 2c 33 48 ff c6 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}