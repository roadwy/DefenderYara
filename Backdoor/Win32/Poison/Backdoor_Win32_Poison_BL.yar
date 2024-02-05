
rule Backdoor_Win32_Poison_BL{
	meta:
		description = "Backdoor:Win32/Poison.BL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {56 33 c9 8b c1 be 1f 00 00 00 99 f7 fe 8a 81 90 01 04 32 c2 88 81 90 1b 00 41 81 f9 10 03 90 01 02 7c df 8d 05 90 01 04 50 8d 05 90 1b 00 ff d0 90 00 } //01 00 
		$a_03_1 = {32 30 32 66 89 54 24 90 01 01 89 5c 24 90 01 01 e8 90 00 } //01 00 
		$a_03_2 = {6e 5c 52 75 c7 84 24 90 01 01 00 00 00 6e 00 00 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}