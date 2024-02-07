
rule TrojanSpy_Win32_KeyLogger_HB_bit{
	meta:
		description = "TrojanSpy:Win32/KeyLogger.HB!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 74 0d dc 6e 41 3b ce 72 f6 } //01 00 
		$a_03_1 = {50 6a 00 8d 85 90 01 03 ff 50 8d 85 90 01 03 ff 50 6a 00 56 c7 85 90 01 03 ff 00 00 00 00 ff 15 90 01 03 00 50 56 ff 15 90 01 03 00 85 c0 7e 0f 0f be 85 90 01 03 ff 50 68 90 01 03 00 eb 29 6a 20 8d 45 bc 50 6a 00 56 ff 15 90 01 03 00 0f b7 c0 c1 e0 10 50 ff 15 90 01 03 00 90 00 } //02 00 
		$a_01_2 = {49 63 6f 6e 43 61 63 68 65 5f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 } //02 00  IconCache_%02d%02d%02d%02d%02d
		$a_01_3 = {00 5b 50 61 75 73 65 5d 00 } //00 00 
		$a_00_4 = {5d 04 00 00 49 } //b1 03 
	condition:
		any of ($a_*)
 
}