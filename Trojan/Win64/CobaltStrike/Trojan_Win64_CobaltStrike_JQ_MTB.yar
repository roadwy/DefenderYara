
rule Trojan_Win64_CobaltStrike_JQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b fe 41 8b c8 b8 90 01 04 33 cf f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 69 c2 90 01 04 2b c8 83 f9 90 01 01 74 90 01 01 ff c7 81 ff 90 01 04 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}