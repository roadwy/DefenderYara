
rule Trojan_Win64_CobaltStrike_FI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 08 48 8b 45 90 01 01 ba 90 01 04 48 f7 75 90 01 01 48 8b 45 90 01 01 48 01 d0 0f b6 10 4c 8b 45 90 01 01 48 8b 45 90 01 01 4c 01 c0 31 ca 88 10 48 83 45 90 01 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}