
rule Trojan_Win64_CobaltStrike_SM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 48 63 8a 90 01 04 89 82 90 01 04 48 90 01 06 45 90 01 03 49 90 01 03 44 90 01 07 48 90 01 06 45 90 01 02 41 90 01 03 44 90 01 03 ff 82 90 01 04 44 90 01 06 41 90 01 02 33 8a 90 01 04 8b 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}