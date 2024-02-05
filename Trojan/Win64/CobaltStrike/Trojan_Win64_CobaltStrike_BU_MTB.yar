
rule Trojan_Win64_CobaltStrike_BU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {ba 80 03 00 00 41 b8 20 00 00 00 48 8b cb ff 15 90 02 04 85 c0 74 2f 48 c7 44 24 28 00 00 00 00 45 33 c9 4c 8b c3 c7 44 24 20 00 00 00 00 33 d2 33 c9 ff 15 90 02 04 48 8b c8 ba 90 02 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}