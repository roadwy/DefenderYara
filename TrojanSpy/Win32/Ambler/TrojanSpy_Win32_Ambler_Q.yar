
rule TrojanSpy_Win32_Ambler_Q{
	meta:
		description = "TrojanSpy:Win32/Ambler.Q,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 5f 73 6b 65 79 5f 25 73 5f 25 73 2e 63 61 62 } //05 00 
		$a_00_1 = {66 69 72 65 66 6f 78 2e 65 00 } //05 00 
		$a_03_2 = {6a 40 6a 1e 53 ff 15 90 01 04 8d 43 05 89 33 50 56 89 45 f8 e8 90 01 04 83 c4 08 88 43 04 8b 45 fc 8d 55 fc 2b fe 52 50 83 ef 05 90 00 } //01 00 
		$a_01_3 = {00 6e 6f 6c 6f 67 00 00 00 61 62 00 00 64 6d 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}