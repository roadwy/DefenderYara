
rule Backdoor_Win32_Gspy_B{
	meta:
		description = "Backdoor:Win32/Gspy.B,SIGNATURE_TYPE_PEHSTR_EXT,1c 02 ffffffa4 01 08 00 00 2c 01 "
		
	strings :
		$a_01_0 = {00 00 67 00 73 00 70 00 79 00 5f 00 62 00 6f 00 74 00 6e 00 65 00 74 00 00 00 } //64 00 
		$a_01_1 = {55 00 4e 00 4b 00 4e 00 4f 00 57 00 4e 00 2d 00 42 00 4f 00 54 00 2d 00 49 00 44 00 } //64 00  UNKNOWN-BOT-ID
		$a_01_2 = {81 e7 ff 00 00 00 0f b6 1c 07 88 1c 02 88 0c 07 02 cb 0f b6 c9 8a 0c 01 30 0c 2e 46 89 7c 24 18 89 5c 24 10 3b 74 24 1c 72 c4 } //28 00 
		$a_01_3 = {7c 02 33 ff 0f b6 14 06 0f b6 1c 2f 03 da 03 cb 81 e1 ff 00 00 00 8a 1c 01 88 1c 06 47 4e 88 14 01 79 d6 } //28 00 
		$a_01_4 = {70 65 5f 69 6e 6a 65 63 74 6f 72 5f 6c 6f 63 6b } //28 00  pe_injector_lock
		$a_01_5 = {62 6f 74 5f 65 78 63 6c 75 73 69 76 65 5f 6c 6f 63 6b } //28 00  bot_exclusive_lock
		$a_01_6 = {65 72 72 2d 34 00 00 00 6e 6f 74 20 69 6d 70 6c 65 6d 65 6e 74 65 64 } //28 00 
		$a_01_7 = {73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 73 00 5f 00 62 00 79 00 5f 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 5c 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 2e 00 6a 00 70 00 67 00 } //00 00  screenshots_by_request\screenshot.jpg
		$a_01_8 = {87 10 00 00 1b 23 c9 ae 1f ee 42 c9 e8 af 16 21 9e 58 00 00 5d 04 00 00 42 cb 02 80 5c 28 00 00 43 cb 02 80 00 00 01 00 22 00 12 00 } //cc 21 
	condition:
		any of ($a_*)
 
}