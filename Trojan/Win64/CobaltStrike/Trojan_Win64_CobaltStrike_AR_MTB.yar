
rule Trojan_Win64_CobaltStrike_AR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 df b3 ff 8b 44 24 90 01 01 20 c7 30 d8 22 44 24 90 01 01 08 f8 88 44 14 90 01 01 42 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}