
rule PWS_Win32_Brothef_A{
	meta:
		description = "PWS:Win32/Brothef.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 00 } //01 00 
		$a_00_1 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //01 00 
		$a_03_2 = {8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 90 01 04 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f3 02 d1 88 54 18 ff 46 8b 45 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}