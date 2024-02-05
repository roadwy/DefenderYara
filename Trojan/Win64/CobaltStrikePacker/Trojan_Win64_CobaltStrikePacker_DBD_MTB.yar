
rule Trojan_Win64_CobaltStrikePacker_DBD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikePacker.DBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {4c 8d 05 5d 8b 02 00 ba 00 00 00 00 b9 00 00 00 00 e8 0b 00 00 00 b8 00 00 00 00 48 83 c4 20 } //03 00 
		$a_01_1 = {48 89 8d 20 04 00 00 48 89 95 28 04 00 00 4c 89 85 30 04 00 00 44 89 8d 38 04 00 00 48 8d 05 1f 8b 02 00 48 89 85 e8 03 00 00 c7 85 e4 03 00 00 62 4a 2b 97 48 c7 85 f8 03 00 00 00 00 00 00 48 c7 85 d8 03 00 00 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}