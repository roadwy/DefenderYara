
rule Backdoor_Win32_Zegost_G{
	meta:
		description = "Backdoor:Win32/Zegost.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 90 01 01 88 10 40 90 01 01 75 f4 90 00 } //01 00 
		$a_03_1 = {3d 00 00 20 03 73 0d 6a 02 56 56 ff 75 90 01 01 ff 15 90 00 } //01 00 
		$a_02_2 = {88 9e b5 00 00 00 c6 45 90 01 01 48 c6 45 90 01 01 65 c6 45 90 01 01 61 c6 45 90 01 01 72 c6 45 90 01 01 74 90 00 } //01 00 
		$a_00_3 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00 25 64 2e 62 61 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}