
rule Backdoor_Win64_CobaltStrikeLoader_ES_dha{
	meta:
		description = "Backdoor:Win64/CobaltStrikeLoader.ES!dha,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 01 d0 0f b6 00 89 c1 8b 85 90 01 04 99 f7 bd 90 01 04 89 d0 48 98 0f b6 84 05 90 01 04 31 c1 8b 85 90 01 04 48 98 48 8b 95 90 01 04 48 01 d0 89 ca 88 10 83 85 90 00 } //04 00 
		$a_03_1 = {49 89 c8 48 89 c1 e8 90 01 04 c7 85 90 01 08 48 8b 95 90 01 04 48 8d 85 90 01 04 48 89 44 24 90 01 01 c7 44 24 90 01 05 41 b9 00 00 00 00 49 89 d0 ba 00 00 00 00 b9 00 00 00 00 48 8b 05 90 01 04 ff d0 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 fc } //03 05 
	condition:
		any of ($a_*)
 
}