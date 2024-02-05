
rule Backdoor_Win64_Plugx_A_dha{
	meta:
		description = "Backdoor:Win64/Plugx.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 69 6e 65 3d 25 64 20 65 72 72 6f 72 3d 25 64 } //01 00 
		$a_01_1 = {56 65 72 73 69 6f 6e 3a 20 6d 61 6a 6f 72 3a 25 64 2c 20 6d 69 6e 6f 72 3a 25 64 } //01 00 
		$a_01_2 = {66 6f 75 6e 64 20 73 65 72 76 69 63 65 5f 72 65 63 6f 72 64 20 74 61 62 6c 65 21 } //01 00 
		$a_01_3 = {ba 2a 00 00 00 48 8d 0d 81 0b 00 00 ff 15 43 0b 00 00 ff 15 e5 0a 00 00 44 8b c0 ba 2b 00 00 00 48 8d 0d 66 0b 00 00 ff 15 28 0b 00 00 90 e9 6f 02 00 00 48 8b 54 24 48 48 8d 8c 24 c0 01 00 00 e8 d8 fd ff ff 8b f8 85 c0 74 3e ff 15 ac 0a 00 00 44 8b c0 ba 32 00 00 00 } //01 00 
		$a_01_4 = {ba 56 00 00 00 48 8d 0d 69 09 00 00 ff 15 2b 09 00 00 ff 15 cd 08 00 00 44 8b c0 ba 57 00 00 00 48 8d 0d 4e 09 00 00 ff 15 10 09 00 00 bb 32 00 00 00 eb 1d } //00 00 
		$a_00_5 = {5d 04 00 } //00 d9 
	condition:
		any of ($a_*)
 
}