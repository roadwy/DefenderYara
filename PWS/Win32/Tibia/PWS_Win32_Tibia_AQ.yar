
rule PWS_Win32_Tibia_AQ{
	meta:
		description = "PWS:Win32/Tibia.AQ,SIGNATURE_TYPE_PEHSTR_EXT,16 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {74 69 62 69 61 63 6c 69 65 6e 74 90 02 10 41 63 63 6f 75 6e 74 3a 90 02 10 50 61 73 73 77 6f 72 64 3a 90 00 } //0a 00 
		$a_02_1 = {53 56 83 c4 f4 8b f0 54 6a 00 68 90 01 04 e8 90 01 04 50 e8 90 01 04 8b 04 24 50 6a 00 68 ff 0f 1f 00 e8 90 01 04 8b d8 8d 44 24 04 50 6a 04 8d 44 24 10 50 56 53 e8 90 01 04 53 e8 90 01 04 8b 44 24 08 83 c4 0c 5e 5b c3 90 00 } //01 00 
		$a_00_2 = {72 65 61 64 70 72 6f 63 65 73 73 6d 65 6d 6f 72 79 } //01 00  readprocessmemory
		$a_00_3 = {67 65 74 77 69 6e 64 6f 77 74 68 72 65 61 64 70 72 6f 63 65 73 73 69 64 } //00 00  getwindowthreadprocessid
	condition:
		any of ($a_*)
 
}