
rule Backdoor_Win32_Etumbot_gen_dha{
	meta:
		description = "Backdoor:Win32/Etumbot.gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff 52 c6 85 90 01 02 ff ff 55 c6 85 90 01 02 ff ff 4e c6 85 90 01 02 ff ff 20 c6 85 90 01 02 ff ff 45 c6 85 90 01 02 ff ff 52 c6 85 90 01 02 ff ff 52 90 09 08 00 3b c3 75 90 01 01 c6 85 90 00 } //01 00 
		$a_02_1 = {f3 ab 66 ab c6 45 90 01 01 62 c6 45 90 01 01 36 c6 45 90 01 01 34 c6 45 90 01 01 5f c6 45 90 01 01 6e c6 45 90 01 01 74 c6 45 90 01 01 6f c6 45 90 01 01 70 c6 45 90 01 01 20 c6 45 90 01 01 65 c6 45 90 01 01 72 c6 45 90 01 01 72 90 00 } //01 00 
		$a_02_2 = {66 ab aa c6 85 90 01 02 ff ff 2f c6 85 90 01 02 ff ff 53 c6 85 90 01 02 ff ff 55 c6 85 90 01 02 ff ff 53 c6 85 90 01 02 ff ff 25 c6 85 90 01 02 ff ff 64 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}