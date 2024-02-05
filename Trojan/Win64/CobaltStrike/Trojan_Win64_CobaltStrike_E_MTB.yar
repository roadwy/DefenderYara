
rule Trojan_Win64_CobaltStrike_E_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 84 24 a0 06 00 00 0f b6 bc 04 10 01 00 00 8b 84 24 a0 06 00 00 99 b9 90 01 01 00 00 00 f7 f9 48 63 ca 48 8b 05 ea 08 01 00 0f b6 04 08 8b d7 33 d0 48 63 8c 24 a0 06 00 00 48 8b 05 fb 08 01 00 88 14 08 eb 9d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}