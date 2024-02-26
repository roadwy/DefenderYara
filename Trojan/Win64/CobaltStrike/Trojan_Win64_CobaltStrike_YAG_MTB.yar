
rule Trojan_Win64_CobaltStrike_YAG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2d 00 04 00 00 0f ba f8 0a 41 88 04 24 49 ff c4 49 83 ff 10 72 31 49 8d 57 01 48 8b c3 48 81 fa 00 10 00 00 72 19 48 83 c2 27 48 8b 5b f8 48 2b c3 48 83 c0 f8 48 83 f8 1f 0f 87 90 01 04 48 8b cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}