
rule Backdoor_Win64_Mozaakai_B{
	meta:
		description = "Backdoor:Win64/Mozaakai.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 03 00 "
		
	strings :
		$a_80_0 = {2e 62 61 7a 61 72 2f 61 70 69 2f 76 } //.bazar/api/v  02 00 
		$a_80_1 = {64 5f 64 65 62 75 67 6c 6f 67 2e 74 78 74 } //d_debuglog.txt  01 00 
		$a_80_2 = {62 65 73 74 67 61 6d 65 2e 62 61 7a 61 72 } //bestgame.bazar  01 00 
		$a_80_3 = {66 6f 72 67 61 6d 65 2e 62 61 7a 61 72 } //forgame.bazar  00 00 
		$a_00_4 = {5d 04 00 00 } //49 21 
	condition:
		any of ($a_*)
 
}