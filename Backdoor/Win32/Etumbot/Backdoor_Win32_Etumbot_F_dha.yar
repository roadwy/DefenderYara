
rule Backdoor_Win32_Etumbot_F_dha{
	meta:
		description = "Backdoor:Win32/Etumbot.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 41 c6 45 f5 75 c6 45 f6 64 c6 45 f7 69 c6 45 f8 6f c6 45 f9 4d c6 45 fa 67 c6 45 fb 72 89 4d e4 } //01 00 
		$a_03_1 = {c6 85 00 fe ff ff 34 c6 85 01 fe ff ff 34 c6 85 02 fe ff ff 33 90 01 03 fe ff ff 00 90 00 } //01 00 
		$a_03_2 = {ee ff ff 2f c6 85 90 01 01 ee ff ff 41 c6 85 90 01 01 ee ff ff 4c c6 85 90 01 01 ee ff ff 49 c6 85 90 01 01 ee ff ff 56 c6 85 90 01 01 ee ff ff 45 c6 85 90 01 01 ee ff ff 20 c6 85 90 01 01 ee ff ff 25 c6 85 90 01 01 ee ff ff 64 c6 85 90 01 01 ee ff ff 20 c6 85 90 01 01 ee ff ff 25 c6 85 90 01 01 ee ff ff 64 c6 85 90 01 01 ee ff ff 0d 90 00 } //01 00 
		$a_03_3 = {ef ff ff 57 c6 85 90 01 01 ef ff ff 49 c6 85 90 01 01 ef ff ff 4e c6 85 90 01 01 ef ff ff 44 c6 85 90 01 01 ef ff ff 4f c6 85 90 01 01 ef ff ff 57 c6 85 90 01 01 ef ff ff 53 c6 85 90 01 01 ef ff ff 20 c6 85 90 01 01 ef ff ff 43 c6 85 90 01 01 ef ff ff 4f c6 85 90 01 01 ef ff ff 4d c6 85 90 01 01 ef ff ff 4d c6 85 90 01 01 ef ff ff 41 c6 85 90 01 01 ef ff ff 4e c6 85 90 01 01 ef ff ff 44 c6 85 90 01 01 ef ff ff 20 c6 85 90 01 01 ef ff ff 53 c6 85 90 01 01 ef ff ff 48 c6 85 90 01 01 ef ff ff 45 c6 85 90 01 01 ef ff ff 4c c6 85 90 01 01 ef ff ff 4c 90 00 } //01 00 
		$a_03_4 = {df ff ff 2f c6 85 90 01 01 df ff ff 53 c6 85 90 01 01 df ff ff 4c c6 85 90 01 01 df ff ff 45 c6 85 90 01 01 df ff ff 45 c6 85 90 01 01 df ff ff 50 c6 85 90 01 01 df ff ff 20 c6 85 90 01 01 df ff ff 25 c6 85 90 01 01 df ff ff 73 c6 85 90 01 01 df ff ff 0d c6 85 90 01 01 df ff ff 0a 90 00 } //01 00 
		$a_01_5 = {c6 44 24 34 48 c6 44 24 35 49 c6 44 24 36 44 c6 44 24 37 45 c6 44 24 38 30 c6 44 24 3c 00 88 5c 24 0a c6 44 24 0d 73 88 5c 24 0f c6 44 24 12 73 88 5c 24 14 } //00 00 
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}