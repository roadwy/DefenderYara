
rule Backdoor_Win32_Beifl_B{
	meta:
		description = "Backdoor:Win32/Beifl.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 c7 44 44 90 01 01 6c 00 66 c7 44 44 90 01 01 6e 00 66 c7 44 44 90 01 01 6b 00 90 00 } //01 00 
		$a_03_1 = {66 c7 84 45 90 01 02 ff ff 6c 00 66 c7 84 45 90 01 02 ff ff 6e 00 66 c7 84 45 90 01 02 ff ff 6b 00 90 00 } //02 00 
		$a_01_2 = {8a 07 3c 11 76 63 25 ff 00 00 00 83 e8 11 47 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}