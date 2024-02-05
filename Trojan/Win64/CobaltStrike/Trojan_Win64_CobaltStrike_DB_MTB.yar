
rule Trojan_Win64_CobaltStrike_DB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 88 04 01 b8 90 01 04 8b 8b 90 01 04 33 8b 90 01 04 ff 43 90 01 01 2b c1 01 05 90 01 04 b8 90 01 04 2b 83 90 01 04 01 83 90 01 04 b8 90 01 04 2b 05 90 01 04 01 43 90 01 01 49 90 01 06 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}