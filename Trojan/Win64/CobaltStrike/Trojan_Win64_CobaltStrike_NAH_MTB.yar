
rule Trojan_Win64_CobaltStrike_NAH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 44 24 38 48 8b 54 24 90 01 01 c1 e0 04 48 c1 fa 02 09 d0 43 88 44 25 90 01 01 49 83 c4 01 71 90 01 06 49 8b 55 90 00 } //01 00 
		$a_03_1 = {48 8b 84 24 98 00 00 00 42 8a 54 25 90 01 01 32 94 1e 90 01 04 42 88 14 20 4c 89 e0 48 83 c0 01 49 89 c4 71 90 01 06 48 ff c3 83 e3 0f e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}