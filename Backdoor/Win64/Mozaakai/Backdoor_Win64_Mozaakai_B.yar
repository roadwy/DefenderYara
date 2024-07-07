
rule Backdoor_Win64_Mozaakai_B{
	meta:
		description = "Backdoor:Win64/Mozaakai.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_80_0 = {2e 62 61 7a 61 72 2f 61 70 69 2f 76 } //.bazar/api/v  3
		$a_80_1 = {64 5f 64 65 62 75 67 6c 6f 67 2e 74 78 74 } //d_debuglog.txt  2
		$a_80_2 = {62 65 73 74 67 61 6d 65 2e 62 61 7a 61 72 } //bestgame.bazar  1
		$a_80_3 = {66 6f 72 67 61 6d 65 2e 62 61 7a 61 72 } //forgame.bazar  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=7
 
}