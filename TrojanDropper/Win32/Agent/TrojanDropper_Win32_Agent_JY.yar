
rule TrojanDropper_Win32_Agent_JY{
	meta:
		description = "TrojanDropper:Win32/Agent.JY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 46 10 89 47 74 8b 46 0c 89 47 70 } //01 00 
		$a_03_1 = {6a 0b ff d0 8b 45 90 01 01 85 c0 74 90 01 01 69 c0 1c 01 00 00 83 c0 04 90 00 } //01 00 
		$a_00_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 20 4c 61 75 6e 63 68 } //01 00 
		$a_00_3 = {47 6c 6f 62 61 6c 5c 5f 5f 73 74 6f 70 } //01 00 
		$a_00_4 = {25 25 55 53 45 52 50 52 4f 46 49 4c 45 25 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 25 73 2e 64 6c 6c } //01 00 
		$a_00_5 = {25 75 2e 25 75 2e 25 75 2e 25 75 3a 36 31 36 38 38 2f 2f 69 6d 67 2f 2f } //00 00 
	condition:
		any of ($a_*)
 
}