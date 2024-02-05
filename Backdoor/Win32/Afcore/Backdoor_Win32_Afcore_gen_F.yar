
rule Backdoor_Win32_Afcore_gen_F{
	meta:
		description = "Backdoor:Win32/Afcore.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {74 0c 6a 01 53 53 53 ff 55 f8 57 ff 56 70 8d 85 90 01 04 50 ff 56 50 90 00 } //02 00 
		$a_03_1 = {68 00 30 10 00 ff 90 17 03 01 04 04 36 76 90 01 01 b6 90 01 04 6a 00 ff 15 90 00 } //01 00 
		$a_03_2 = {8a 4c 01 28 32 90 03 01 04 0e 4e 90 01 01 90 17 02 05 05 8b 56 90 01 01 8b 96 90 01 04 88 0c 10 90 00 } //01 00 
		$a_03_3 = {8a 54 0a 28 8b 7e 90 01 01 8d 86 90 01 04 32 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}