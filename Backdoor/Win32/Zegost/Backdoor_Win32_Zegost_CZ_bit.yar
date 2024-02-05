
rule Backdoor_Win32_Zegost_CZ_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 46 75 55 70 67 72 61 64 72 73 } //01 00 
		$a_01_1 = {88 54 24 25 c6 44 24 26 6c c6 44 24 28 69 c6 44 24 29 70 88 5c 24 2b 88 4c 24 2c c6 44 24 2d 73 c6 44 24 2e 66 c6 44 24 2f 73 } //00 00 
	condition:
		any of ($a_*)
 
}