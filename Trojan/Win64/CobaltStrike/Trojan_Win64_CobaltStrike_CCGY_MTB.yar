
rule Trojan_Win64_CobaltStrike_CCGY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 54 81 90 01 01 81 74 95 90 01 05 48 63 14 81 81 74 95 90 01 05 48 83 c0 90 01 01 48 83 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}