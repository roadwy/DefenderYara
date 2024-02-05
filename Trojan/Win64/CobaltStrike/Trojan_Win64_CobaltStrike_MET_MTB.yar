
rule Trojan_Win64_CobaltStrike_MET_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 04 11 48 83 c2 90 01 01 8b 8b 90 01 04 8b 83 90 01 04 03 c1 35 90 01 04 29 43 90 01 01 8b 43 90 01 01 83 e8 90 01 01 01 43 90 01 01 8b 83 90 01 04 33 c1 35 90 01 04 29 83 90 01 04 8b 83 90 01 04 01 83 90 01 04 8b 83 90 01 04 29 43 90 01 01 48 81 fa 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}