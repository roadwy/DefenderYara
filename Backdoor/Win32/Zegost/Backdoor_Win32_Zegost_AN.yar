
rule Backdoor_Win32_Zegost_AN{
	meta:
		description = "Backdoor:Win32/Zegost.AN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff 77 c6 85 90 01 02 ff ff 77 88 9d 90 02 10 c6 84 1d 90 01 04 03 c6 84 1d 90 01 04 63 c6 84 1d 90 01 04 6f c6 84 1d 90 01 04 6d 80 a4 1d 90 01 04 00 90 00 } //01 00 
		$a_03_1 = {ff 45 08 81 7d 08 64 19 00 00 0f 8c 90 01 02 ff ff 90 00 } //01 00 
		$a_01_2 = {8b c1 6a 03 99 5f f7 ff 8a 04 31 83 fa 01 75 0c 3c 20 7e 15 3c 7f } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}