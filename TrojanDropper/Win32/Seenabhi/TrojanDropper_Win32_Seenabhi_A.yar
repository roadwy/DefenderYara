
rule TrojanDropper_Win32_Seenabhi_A{
	meta:
		description = "TrojanDropper:Win32/Seenabhi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 4d c6 45 fd 5a 88 5d fe c6 45 f4 d8 88 5d f5 88 5d f6 } //02 00 
		$a_01_1 = {c6 45 f4 4a 51 50 c6 45 f5 75 c6 45 f6 73 c6 45 f7 74 c6 45 f8 54 c6 45 f9 65 c6 45 fa 6d c6 45 fb 70 c6 45 fc 46 c6 45 fd 75 c6 45 fe 6e } //01 00 
		$a_01_2 = {c6 45 b0 77 3b c3 c6 45 b1 69 c6 45 b2 6e c6 45 b3 6c c6 45 b4 6f c6 45 b5 67 c6 45 b6 2e c6 45 b7 6c c6 45 b8 6e c6 45 b9 6b } //01 00 
		$a_01_3 = {c6 45 c8 70 c6 45 c9 73 c6 45 ca 6c c6 45 cb 6f c6 45 cc 67 c6 45 cd 2e c6 45 ce 74 c6 45 cf 78 c6 45 d0 74 } //00 00 
	condition:
		any of ($a_*)
 
}