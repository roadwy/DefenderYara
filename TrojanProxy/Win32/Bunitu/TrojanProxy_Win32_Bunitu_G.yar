
rule TrojanProxy_Win32_Bunitu_G{
	meta:
		description = "TrojanProxy:Win32/Bunitu.G,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0a 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {ba fd 13 54 50 89 10 81 00 49 40 00 00 ff 00 ff 00 } //0a 00 
		$a_03_1 = {2b d2 81 c2 90 01 04 89 15 90 01 04 81 ea 90 01 04 4a 83 ea 47 4a 4a 90 00 } //0a 00 
		$a_01_2 = {81 2c 24 61 75 17 00 8f 00 c7 40 04 03 34 3f 32 ff 48 04 ff 48 04 81 68 04 9b c7 0b 00 ff 48 04 } //0a 00 
		$a_01_3 = {8b 34 8a 03 f5 33 ff c1 cf 13 ac 03 f8 } //0a 00 
		$a_03_4 = {8b 34 8a 03 f5 33 ff c1 cf 13 ac 03 f8 85 c0 75 90 01 01 3b fb 75 90 01 01 5a 8b 5a 24 03 dd 66 8b 0c 4b 8b 5a 1c 03 dd 8b 04 8b 8b c8 90 00 } //0a 00 
		$a_00_5 = {c7 00 3a 2a 3a 45 5a } //00 00 
		$a_00_6 = {5d 04 00 00 74 0c 03 80 5c 20 } //00 00 
	condition:
		any of ($a_*)
 
}