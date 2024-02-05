
rule TrojanSpy_Win32_Weecnaw_D_bit{
	meta:
		description = "TrojanSpy:Win32/Weecnaw.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 63 61 74 20 2d 6c 20 2d 70 20 34 30 30 30 20 2d 72 20 74 63 70 } //01 00 
		$a_01_1 = {64 65 6c 20 22 25 25 7e 66 30 22 26 65 78 69 74 20 2f 62 } //01 00 
		$a_01_2 = {25 54 45 4d 50 25 5c 70 6f 77 65 72 63 61 74 2e 70 73 31 } //01 00 
		$a_01_3 = {25 54 45 4d 50 25 5c 6c 6f 6f 70 63 2e 63 6d 64 } //00 00 
	condition:
		any of ($a_*)
 
}