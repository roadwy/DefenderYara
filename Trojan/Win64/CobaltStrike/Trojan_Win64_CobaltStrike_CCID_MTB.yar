
rule Trojan_Win64_CobaltStrike_CCID_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 04 01 83 f0 08 83 f0 58 48 63 4c 24 90 01 01 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}