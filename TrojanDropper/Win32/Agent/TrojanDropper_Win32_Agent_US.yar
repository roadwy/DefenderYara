
rule TrojanDropper_Win32_Agent_US{
	meta:
		description = "TrojanDropper:Win32/Agent.US,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 65 89 5d f0 e8 90 01 02 ff ff 83 c4 0c ff 75 f0 89 45 f4 ff 15 90 01 04 8b f8 33 c0 39 5d f4 76 09 fe 0c 38 40 3b 45 f4 72 f7 ff 15 90 01 04 6a 1a 59 33 d2 f7 f1 68 42 10 00 00 90 00 } //01 00 
		$a_02_1 = {50 c6 45 f9 2e c6 45 fa 65 c6 45 fb 78 c6 45 fc 65 88 5d fd 80 c2 61 88 55 f8 ff 15 90 01 04 53 8b f0 8d 45 ec 50 ff 75 f4 57 56 ff 15 90 01 04 56 ff 15 90 01 04 8b 35 90 01 04 53 53 53 8d 45 f8 50 53 53 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}