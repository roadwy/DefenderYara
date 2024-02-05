
rule Backdoor_Win32_Zegost_BL{
	meta:
		description = "Backdoor:Win32/Zegost.BL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 02 6a 00 68 00 fc ff ff 90 01 01 ff 15 90 00 } //01 00 
		$a_02_1 = {8a 1c 16 3a 1c 2a 75 90 01 01 42 3b d1 7c 90 00 } //01 00 
		$a_01_2 = {00 50 50 50 50 50 50 00 } //01 00 
		$a_00_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 68 69 } //00 00 
	condition:
		any of ($a_*)
 
}