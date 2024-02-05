
rule Backdoor_Win32_Throabot_gen_A{
	meta:
		description = "Backdoor:Win32/Throabot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 18 00 00 00 8b 40 30 0f b6 40 02 85 c0 75 02 eb 04 c6 45 ff 01 58 80 7d ff 00 75 0a 6a 0a ff 15 } //01 00 
		$a_03_1 = {7e 10 80 34 3e c9 57 46 e8 90 01 02 00 00 3b f0 59 7c f0 90 00 } //01 00 
		$a_01_2 = {83 c4 14 3d 80 7d 05 00 0f 85 } //01 00 
		$a_01_3 = {74 26 56 0f be c9 c1 e0 04 03 c1 8b c8 42 81 e1 00 00 00 f0 74 07 8b f1 c1 ee 18 33 c6 f7 d1 23 c1 8a 0a 84 c9 75 dc } //00 00 
	condition:
		any of ($a_*)
 
}