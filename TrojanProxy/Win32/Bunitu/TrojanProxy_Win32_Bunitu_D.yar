
rule TrojanProxy_Win32_Bunitu_D{
	meta:
		description = "TrojanProxy:Win32/Bunitu.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 40 ba 0d 54 54 50 89 10 83 00 39 ff 00 ff 00 fe 0d } //01 00 
		$a_01_1 = {8f 00 c7 40 04 69 6c 33 32 ff 48 04 ff 48 04 83 68 04 01 ff 48 04 68 } //01 00 
		$a_01_2 = {c7 00 3a 2a 3a 45 5a } //01 00 
		$a_01_3 = {3c 62 69 67 3e 20 6e 6f 74 20 66 6f 75 6e 64 20 3c 62 69 67 3e } //01 00  <big> not found <big>
		$a_01_4 = {2b c0 b8 02 00 00 00 c1 e0 03 8b d0 8b ff 8b d0 d1 e0 03 c2 66 83 c0 06 48 86 e0 } //01 00 
		$a_01_5 = {81 c1 7b 2c 00 00 6a 00 6a 2c 51 ff 35 } //00 00 
	condition:
		any of ($a_*)
 
}