
rule Backdoor_Win32_PcClient_AY{
	meta:
		description = "Backdoor:Win32/PcClient.AY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {51 8b 54 24 10 8d 44 24 00 6a 00 50 8b 44 24 14 6a 00 6a 00 52 8b 54 24 1c 50 8b 81 c4 08 00 00 52 50 c7 44 24 20 00 00 00 00 ff 15 } //01 00 
		$a_01_1 = {89 44 24 08 2d 38 44 44 24 08 2d 36 41 04 50 68 2d 31 30 00 61 25 8b ce e8 } //01 00 
		$a_01_2 = {8a 44 24 20 f6 d8 1a c0 24 01 fe c8 88 46 0c } //01 00 
		$a_01_3 = {8a 0c 32 80 f9 30 7c 05 80 f9 39 7e 05 80 f9 2e 75 0e 42 } //00 00 
	condition:
		any of ($a_*)
 
}