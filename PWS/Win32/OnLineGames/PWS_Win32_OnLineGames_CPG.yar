
rule PWS_Win32_OnLineGames_CPG{
	meta:
		description = "PWS:Win32/OnLineGames.CPG,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6d 73 70 6c 61 79 33 32 2e 64 6c 6c } //0a 00 
		$a_00_1 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //0a 00 
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00 
		$a_01_3 = {00 4a 75 6d 70 4f 6e } //01 00 
		$a_01_4 = {00 4a 75 6d 70 4f 66 66 } //00 00 
	condition:
		any of ($a_*)
 
}