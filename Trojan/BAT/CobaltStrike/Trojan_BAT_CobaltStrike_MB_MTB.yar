
rule Trojan_BAT_CobaltStrike_MB_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 11 0a 9a 1f 10 28 90 01 03 0a 86 6f 90 01 03 0a 00 11 0a 17 d6 13 0a 11 0a 11 09 31 df 90 00 } //02 00 
		$a_03_1 = {da 04 d6 1f 1a 5d 13 07 07 11 06 28 90 01 03 0a 11 07 d6 90 00 } //02 00 
		$a_01_2 = {50 6f 6f 6c 41 6e 64 53 70 61 44 65 70 6f 74 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //00 00  PoolAndSpaDepot.My.Resources
	condition:
		any of ($a_*)
 
}