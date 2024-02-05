
rule Backdoor_Win32_Afcore_gen_E{
	meta:
		description = "Backdoor:Win32/Afcore.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 00 30 10 00 ff 76 90 01 01 6a 00 ff 15 90 17 03 05 05 05 90 09 13 00 e9 90 09 10 00 eb 90 09 10 00 75 90 00 } //01 00 
		$a_03_1 = {8a 4c 01 28 32 4e 90 01 01 8b 56 90 01 01 88 0c 10 90 00 } //01 00 
		$a_03_2 = {8a 0c 01 32 4e 90 01 01 8b 56 90 01 01 88 0c 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}