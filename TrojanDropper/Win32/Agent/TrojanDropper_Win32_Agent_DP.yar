
rule TrojanDropper_Win32_Agent_DP{
	meta:
		description = "TrojanDropper:Win32/Agent.DP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 59 25 6d 25 64 00 00 2e 69 6e 69 00 00 00 00 5c 53 65 72 76 65 72 2e 74 6d 70 } //01 00 
		$a_00_1 = {3e 20 6e 75 6c 00 00 20 2f 63 20 20 64 65 6c } //01 00 
		$a_00_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //01 00 
		$a_03_3 = {51 ff d5 8d 90 01 04 00 00 6a 00 52 ff 15 90 01 03 00 83 f8 1f 7e 1b 68 88 13 00 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}