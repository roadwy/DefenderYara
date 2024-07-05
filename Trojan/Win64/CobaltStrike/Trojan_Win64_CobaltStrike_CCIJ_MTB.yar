
rule Trojan_Win64_CobaltStrike_CCIJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 f0 83 e0 90 01 01 45 8a 7c 05 90 01 01 ff 90 01 01 45 31 fe 44 88 34 33 48 ff c6 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}