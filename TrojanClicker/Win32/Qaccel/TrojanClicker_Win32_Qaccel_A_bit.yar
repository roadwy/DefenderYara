
rule TrojanClicker_Win32_Qaccel_A_bit{
	meta:
		description = "TrojanClicker:Win32/Qaccel.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 45 36 32 32 44 31 38 35 43 31 42 43 37 36 30 45 34 30 43 43 44 42 32 34 39 42 39 35 36 31 32 } //01 00 
		$a_03_1 = {5c 51 51 41 63 63 65 6c 65 78 2e 65 78 65 90 02 05 5c 54 65 6e 63 65 6e 74 90 00 } //01 00 
		$a_01_2 = {43 57 65 62 42 72 6f 77 73 65 72 32 } //01 00 
		$a_03_3 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 90 02 10 2e 63 6f 6d 2f 3f 74 6e 3d 25 73 90 02 20 5f 68 61 6f 5f 70 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}