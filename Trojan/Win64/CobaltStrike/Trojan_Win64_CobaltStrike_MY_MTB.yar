
rule Trojan_Win64_CobaltStrike_MY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {66 89 45 0a 45 33 c0 ba 01 00 00 00 b9 02 00 00 00 ff 15 90 01 04 48 89 45 38 41 b8 10 00 00 00 48 8d 55 08 48 8b 4d 38 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}