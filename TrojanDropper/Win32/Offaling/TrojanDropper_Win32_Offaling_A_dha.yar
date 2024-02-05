
rule TrojanDropper_Win32_Offaling_A_dha{
	meta:
		description = "TrojanDropper:Win32/Offaling.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 33 c9 ff 15 90 01 01 04 00 00 33 c9 ff 15 90 01 01 04 00 00 33 c9 ff 15 90 01 01 04 00 00 b8 01 00 00 00 48 83 c4 28 c3 90 00 } //01 00 
		$a_01_1 = {36 39 46 46 30 30 30 30 46 44 30 38 34 31 43 31 45 42 31 30 34 35 36 39 44 42 30 33 46 37 36 35 32 33 34 31 32 42 46 42 38 31 45 46 46 42 31 32 42 37 31 43 } //01 00 
		$a_01_2 = {6d 73 63 6f 72 65 65 2e 64 6c 6c 00 43 6f 72 42 69 6e 64 54 6f 52 75 6e 74 69 6d 65 45 78 } //00 00 
	condition:
		any of ($a_*)
 
}