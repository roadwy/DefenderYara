
rule Trojan_Win64_CobaltStrike_TR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 f0 83 e0 90 01 01 41 8a 04 04 32 44 35 90 01 01 88 04 33 48 ff c6 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}