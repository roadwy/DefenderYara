
rule Backdoor_Win64_CobaltStrike_AA_MTB{
	meta:
		description = "Backdoor:Win64/CobaltStrike.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {55 48 89 e5 48 83 ec 50 c7 45 e4 90 01 04 8b 05 90 01 01 2a 03 00 89 c0 41 b9 90 01 04 4c 8d 05 90 01 02 03 00 48 89 c2 48 8d 0d 90 01 01 29 03 00 e8 90 01 01 ff ff ff 48 8d 0d 90 01 02 03 00 48 8b 05 90 01 02 03 90 00 } //0a 00 
		$a_00_1 = {55 48 89 e5 48 83 ec 10 48 89 4d 10 48 89 55 18 4c 89 45 20 4c 89 4d 28 c7 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}