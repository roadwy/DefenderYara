
rule Backdoor_Win32_WipBot_B{
	meta:
		description = "Backdoor:Win32/WipBot.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 0c 3a 88 d0 32 01 42 83 f0 90 01 01 83 fa 90 01 01 88 01 75 ee 90 00 } //01 00 
		$a_01_1 = {8d ba 5f f3 6e 3c 89 fe c1 ee 10 89 f2 30 14 01 40 3b 43 04 72 e4 5b b8 01 00 00 00 5e 5f 5d c3 } //01 00 
		$a_01_2 = {c7 47 20 90 90 90 90 c7 47 24 90 90 90 c3 c7 47 28 50 51 48 83 c7 47 2c ec 28 48 b9 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}