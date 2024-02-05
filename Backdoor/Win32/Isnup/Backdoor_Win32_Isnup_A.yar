
rule Backdoor_Win32_Isnup_A{
	meta:
		description = "Backdoor:Win32/Isnup.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 84 81 00 00 00 56 6a 01 6a 25 8d 44 24 28 50 6a 00 ff 15 } //01 00 
		$a_01_1 = {3c 3b 74 09 8a 44 1e 01 46 84 c0 75 f3 } //01 00 
		$a_01_2 = {85 ff b0 45 7e 14 56 8b 74 24 0c 30 04 31 2c 06 b2 14 f6 ea 41 3b cf 7c f2 } //00 00 
	condition:
		any of ($a_*)
 
}