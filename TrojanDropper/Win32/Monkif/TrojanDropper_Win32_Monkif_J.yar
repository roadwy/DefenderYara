
rule TrojanDropper_Win32_Monkif_J{
	meta:
		description = "TrojanDropper:Win32/Monkif.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 8b 74 24 0c 2b f7 90 02 09 2a c2 2c 90 01 01 90 02 07 42 3b 54 24 10 90 02 03 7c 90 00 } //1
		$a_02_1 = {6d 73 30 30 31 2e 74 6d 70 90 02 05 54 68 72 65 61 64 69 6e 67 4d 6f 64 65 6c 90 02 05 70 61 72 74 6d 65 6e 74 90 02 05 25 73 25 73 5c 25 73 00 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Monkif_J_2{
	meta:
		description = "TrojanDropper:Win32/Monkif.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 74 24 0c 2b f7 8a 84 16 90 01 04 2a c2 2c 4f 88 82 90 01 04 42 3b 54 24 10 7c 90 00 } //1
		$a_03_1 = {50 68 01 00 00 80 ff 55 f4 85 c0 75 3e ff 75 08 ff d6 50 ff 75 08 6a 01 53 53 ff 75 fc ff 55 f8 85 c0 75 27 bf 90 01 04 57 ff d6 50 57 6a 01 53 68 90 01 04 ff 75 fc ff 55 f8 85 c0 75 0b ff 75 fc ff 55 f0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Monkif_J_3{
	meta:
		description = "TrojanDropper:Win32/Monkif.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 74 24 0c 2b f7 8d 8a 90 01 04 8a 04 0e 2a c2 2c 4f 42 3b 54 24 10 88 01 7c ea 90 00 } //1
		$a_03_1 = {50 68 01 00 00 80 ff 55 f4 85 c0 75 3e ff 75 08 ff d6 50 ff 75 08 6a 01 53 53 ff 75 fc ff 55 f8 85 c0 75 27 bf 90 01 04 57 ff d6 50 57 6a 01 53 68 90 01 04 ff 75 fc ff 55 f8 85 c0 75 0b ff 75 fc ff 55 f0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}