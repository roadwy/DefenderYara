
rule Backdoor_Win32_Mdmbot_G_dha{
	meta:
		description = "Backdoor:Win32/Mdmbot.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 75 00 69 00 64 00 2e 00 61 00 78 00 00 00 } //01 00 
		$a_01_1 = {25 00 25 00 54 00 45 00 4d 00 50 00 25 00 25 00 5c 00 25 00 73 00 5f 00 70 00 2e 00 61 00 78 00 00 00 } //01 00 
		$a_01_2 = {8d 8c 3e 10 02 00 00 8a 14 3e 8a 1c 01 32 da 88 1c 01 8b 54 3e 04 40 3b c2 72 ec } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}