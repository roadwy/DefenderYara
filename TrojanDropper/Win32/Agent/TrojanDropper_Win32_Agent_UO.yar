
rule TrojanDropper_Win32_Agent_UO{
	meta:
		description = "TrojanDropper:Win32/Agent.UO,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 } //01 00 
		$a_01_1 = {66 81 3a 4d 5a 74 09 81 ea 00 00 01 00 90 eb ef 90 8b fa 8b 57 3c 90 8b 54 17 78 8d 54 17 1c } //01 00 
		$a_01_2 = {ff 74 24 04 ff 53 dc 6a 00 68 80 00 00 00 6a 02 6a 00 90 6a 00 68 00 00 00 40 90 50 ff 53 ec 40 74 46 48 50 56 6a 00 54 83 2c 24 50 } //01 00 
		$a_01_3 = {50 ff 53 e4 5e 90 ff 53 e8 86 ed 8b 54 24 04 90 8b 04 24 6a 01 6a 00 6a 00 86 ed 50 6a 00 90 6a 00 ff d2 03 fd } //00 00 
	condition:
		any of ($a_*)
 
}