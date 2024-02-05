
rule TrojanSpy_Win32_Keatep_E{
	meta:
		description = "TrojanSpy:Win32/Keatep.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {74 17 8b 55 f8 81 e2 ff ff 00 00 d1 fa 81 f2 01 a0 00 00 } //02 00 
		$a_01_1 = {6a 65 6f 52 33 57 71 31 00 } //01 00 
		$a_02_2 = {7c 24 70 61 73 73 3d 00 90 09 24 00 66 61 63 65 62 6f 6f 6b 2e 90 00 } //01 00 
		$a_02_3 = {26 72 65 64 69 72 65 63 74 5f 74 6f 3d 00 00 00 50 4f 53 54 90 02 8f 77 70 2d 6c 6f 67 69 6e 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}