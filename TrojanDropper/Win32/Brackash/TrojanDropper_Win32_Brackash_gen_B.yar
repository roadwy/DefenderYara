
rule TrojanDropper_Win32_Brackash_gen_B{
	meta:
		description = "TrojanDropper:Win32/Brackash.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {75 7f 83 7b 04 00 7e 79 8d 55 fc 8b 43 04 e8 90 01 02 ff ff 8b 55 fc b8 90 01 04 e8 90 01 02 f8 ff 85 c0 7e 34 90 00 } //0a 00 
		$a_03_1 = {84 c0 75 3f 68 90 01 04 68 90 01 04 8b 0d 90 01 04 b2 01 a1 90 01 04 e8 90 01 02 f9 ff 8b f0 8d 45 ec b9 90 01 04 8b 55 fc e8 90 01 02 f8 ff 8b 55 ec 8b c6 e8 90 01 02 f9 ff 8b c6 e8 90 01 02 f8 ff 8d 45 e8 b9 90 01 04 8b 55 fc e8 90 01 02 f8 ff 8b 45 e8 e8 90 01 02 f8 ff 84 c0 75 3f 90 00 } //02 00 
		$a_03_2 = {7a 71 64 62 90 03 01 01 31 32 2e 64 6c 6c 00 90 00 } //02 00 
		$a_03_3 = {6d 79 64 6c 6c 90 03 01 01 31 32 00 90 00 } //02 00 
		$a_03_4 = {72 61 6e 64 6f 6d 66 75 6e 63 69 6f 6e 64 69 72 6d 65 6d 6f 72 79 90 03 04 04 6c 69 6b 65 68 61 74 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}