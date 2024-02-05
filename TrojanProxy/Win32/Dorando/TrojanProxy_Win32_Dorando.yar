
rule TrojanProxy_Win32_Dorando{
	meta:
		description = "TrojanProxy:Win32/Dorando,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 6d 65 73 73 65 6e 67 65 72 20 64 69 72 3d 69 6e 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 20 70 72 6f 74 6f 63 6f 6c 3d 54 43 50 20 6c 6f 63 61 6c 70 6f 72 74 3d 25 64 } //01 00 
		$a_01_1 = {70 6f 72 74 6f 70 65 6e 69 6e 67 20 54 43 50 20 25 64 20 6d 65 73 73 65 6e 67 65 72 20 45 4e 41 42 4c 45 20 41 4c 4c } //01 00 
		$a_01_2 = {74 67 6b 62 61 73 65 2e 64 61 74 } //01 00 
		$a_01_3 = {74 77 61 69 6e 5f 33 32 5c 75 73 72 2e 64 61 74 } //01 00 
		$a_00_4 = {8b 94 24 18 01 00 00 8b 4c 24 0c 33 c0 8b fe 8b d9 c1 e7 06 03 df 0f be 3c 10 03 f3 2b f8 49 03 f7 40 83 f8 10 7c e6 } //00 00 
	condition:
		any of ($a_*)
 
}