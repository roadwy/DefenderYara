
rule TrojanClicker_Win32_Agent_S{
	meta:
		description = "TrojanClicker:Win32/Agent.S,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2e 62 65 73 74 64 66 67 2e 69 6e 66 6f 3a 90 02 04 2f 90 02 10 2e 70 68 70 3f 67 67 3d 90 00 } //01 00 
		$a_00_1 = {73 3d 73 2b 68 65 78 5b 61 2f 31 36 25 31 36 5d 2b 68 65 78 5b 61 25 31 36 5d 2b 23 5b 62 3e 30 2c 27 2d 27 2c 27 27 5d } //01 00 
		$a_00_2 = {73 64 66 61 69 72 70 6f 72 74 2e 69 6e 66 6f 3a 37 37 37 } //01 00 
		$a_00_3 = {5c 53 65 6c 66 44 65 6c 2e 64 6c 6c } //01 00 
		$a_00_4 = {5c 72 72 66 64 73 5f } //01 00 
		$a_00_5 = {54 72 61 63 6b 50 6f 70 75 70 4d 65 6e 75 } //00 00 
	condition:
		any of ($a_*)
 
}