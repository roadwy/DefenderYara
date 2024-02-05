
rule Backdoor_Win32_Etumbot_C_dha{
	meta:
		description = "Backdoor:Win32/Etumbot.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 85 18 e4 ff ff 04 00 00 00 c7 85 64 ff ff ff 4d 6f 7a 69 c7 85 68 ff ff ff 6c 6c 61 2f c7 85 6c ff ff ff 35 2e 30 20 c7 85 70 ff ff ff 28 57 69 6e c7 85 74 ff ff ff 64 6f 77 73 c7 85 78 ff ff ff 20 4e 54 20 c7 85 7c ff ff ff 36 2e 31 3b c7 45 80 20 72 76 3a c7 45 84 34 33 2e 30 c7 45 88 29 20 47 65 c7 45 8c 63 6b 6f 2f c7 45 90 32 30 31 30 c7 45 94 30 31 30 31 c7 45 98 20 46 69 72 c7 45 9c 65 66 6f 78 c7 45 a0 2f 34 33 2e } //01 00 
		$a_03_1 = {ff ff ff 53 6f 66 74 c7 85 90 01 01 ff ff ff 77 61 72 65 c7 85 90 01 01 ff ff ff 5c 4d 69 63 c7 85 90 01 01 ff ff ff 72 6f 73 6f c7 85 90 01 01 ff ff ff 66 74 5c 57 c7 85 90 01 01 ff ff ff 69 6e 64 6f 90 00 } //01 00 
		$a_01_2 = {c7 45 d4 6f 72 5b 25 c7 45 d8 64 5d 2e 0d } //01 00 
		$a_01_3 = {c7 45 88 2f 53 44 55 c7 45 8c 25 64 3d 25 c7 45 90 64 2e 63 67 c7 45 94 69 3f 25 73 } //01 00 
		$a_03_4 = {ff ff ff 2f 44 45 53 c7 85 90 01 01 ff ff ff 25 64 3d 25 c7 85 90 01 01 ff ff ff 64 2e 63 67 c7 85 90 01 01 ff ff ff 69 3f 25 73 90 00 } //01 00 
		$a_01_5 = {c7 45 90 4d 6f 7a 69 c7 45 94 6c 6c 61 2f c7 45 98 34 2e 30 20 c7 45 9c 28 63 6f 6d c7 45 a0 70 61 74 69 c7 45 a4 62 6c 65 3b c7 45 a8 20 4d 53 49 c7 45 ac 45 20 37 2e c7 45 b0 30 3b 20 57 c7 45 b4 69 6e 33 32 } //00 00 
		$a_00_6 = {5d 04 00 } //00 4d 
	condition:
		any of ($a_*)
 
}