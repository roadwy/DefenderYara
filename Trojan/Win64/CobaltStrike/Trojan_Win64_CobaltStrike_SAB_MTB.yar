
rule Trojan_Win64_CobaltStrike_SAB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 03 48 90 01 02 39 f8 89 c2 7c 90 0a 16 00 83 e2 90 01 01 8a 54 15 90 01 01 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}