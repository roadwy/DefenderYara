
rule TrojanDropper_Win32_Agent_EB{
	meta:
		description = "TrojanDropper:Win32/Agent.EB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 65 7a 68 65 6e 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 00 25 73 2c 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 25 73 79 73 74 65 6d 25 } //01 00 
		$a_03_1 = {c2 10 00 81 fe 08 05 00 00 75 1e 68 34 12 00 00 53 ff 15 90 01 02 40 00 b9 e8 ba 40 00 e8 90 01 02 00 00 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}