
rule TrojanClicker_Win32_Agent_Y{
	meta:
		description = "TrojanClicker:Win32/Agent.Y,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 73 5f 67 5f 6c 5f 32 30 39 2e 62 61 74 } //01 00 
		$a_01_1 = {5c 78 7a 6f 6b 2e 62 61 74 } //01 00 
		$a_01_2 = {63 3a 5c 7a 77 6f 6b } //01 00 
		$a_01_3 = {6e 75 6f 6c 64 39 31 39 } //00 00 
	condition:
		any of ($a_*)
 
}