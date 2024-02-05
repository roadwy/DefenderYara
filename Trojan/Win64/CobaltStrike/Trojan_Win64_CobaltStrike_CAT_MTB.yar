
rule Trojan_Win64_CobaltStrike_CAT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 95 10 01 00 00 48 8d 8d b0 00 00 00 e8 90 01 04 48 8b 8d 38 03 00 00 ff d0 90 90 48 8d 8d b0 00 00 00 e8 90 01 04 48 8b 95 50 01 00 00 48 8d 8d b0 00 00 00 e8 90 01 04 ff d0 8b d8 48 8b 95 58 01 00 00 48 8d 8d b0 00 00 00 e8 90 01 04 b9 e8 03 00 00 ff d0 48 8b 95 50 01 00 00 48 8d 8d b0 00 00 00 e8 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}