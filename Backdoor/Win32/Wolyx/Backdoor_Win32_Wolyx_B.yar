
rule Backdoor_Win32_Wolyx_B{
	meta:
		description = "Backdoor:Win32/Wolyx.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 79 6f 75 00 } //01 00 
		$a_01_1 = {6d 73 73 65 63 65 73 00 ff ff ff ff 0a 00 00 00 73 70 69 64 65 72 67 61 74 65 00 00 ff ff ff ff 08 00 00 00 75 66 73 65 61 67 6e 74 00 } //01 00 
		$a_01_2 = {49 45 69 6e 66 6f 2e 64 6c 6c 00 57 53 50 53 74 61 72 74 75 70 00 } //00 00 
		$a_01_3 = {00 5d } //04 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Wolyx_B_2{
	meta:
		description = "Backdoor:Win32/Wolyx.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 02 6a 00 6a 02 68 00 00 00 40 a1 90 01 04 8b 00 50 e8 90 01 04 8b f0 83 fe ff 74 90 01 01 6a 00 8d 45 fc 50 57 8d 45 f8 e8 90 01 04 50 56 e8 90 01 04 56 e8 90 00 } //01 00 
		$a_02_1 = {64 ff 30 64 89 20 c6 45 f7 00 8d 45 ec 50 68 3f 00 0f 00 6a 00 8b 45 0c e8 90 01 04 50 8b 45 10 50 a1 90 01 04 8b 00 ff d0 85 c0 90 00 } //01 00 
		$a_01_2 = {41 44 31 38 42 42 34 35 42 32 37 43 38 39 34 36 41 44 31 39 41 30 37 36 38 45 37 34 39 34 35 38 41 45 32 39 41 30 35 42 42 32 34 37 38 38 34 37 41 46 30 32 41 31 35 41 38 44 37 37 38 45 } //00 00 
	condition:
		any of ($a_*)
 
}