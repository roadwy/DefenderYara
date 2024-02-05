
rule Backdoor_Win32_Flacher_A_dha{
	meta:
		description = "Backdoor:Win32/Flacher.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 09 80 34 38 7e 40 3b c3 72 f7 6a 00 8d 45 f0 50 53 57 56 ff 15 } //01 00 
		$a_01_1 = {c7 85 18 fd ff ff 64 00 00 00 ff b5 20 fd ff ff c7 85 10 fd ff ff 05 01 00 00 ff 15 } //01 00 
		$a_01_2 = {2b c7 d1 f8 50 51 6a 2b ff b5 60 fe ff ff ff d6 6a 01 53 6a 03 53 53 ff } //01 00 
		$a_01_3 = {69 c0 44 33 22 11 41 0f af c8 6a 04 8d 44 24 40 50 57 56 89 4c 24 } //01 00 
		$a_03_4 = {8a 08 40 84 c9 75 f9 2b c2 53 8b d8 80 7c 3b ff 90 01 01 75 3e 90 00 } //00 00 
		$a_00_5 = {87 } //10 00 
	condition:
		any of ($a_*)
 
}