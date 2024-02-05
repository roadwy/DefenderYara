
rule TrojanSpy_Win32_Rumish_B{
	meta:
		description = "TrojanSpy:Win32/Rumish.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 42 72 6f 77 73 65 72 2e 48 65 6c 70 90 02 03 5c 42 72 6f 77 73 65 72 2e 48 65 6c 70 5c 52 65 6c 65 61 73 65 5c 72 76 72 73 2e 70 64 62 90 00 } //01 00 
		$a_01_1 = {26 62 72 77 73 76 3d 00 26 62 72 77 73 3d 00 00 26 69 65 3d 38 00 } //00 00 
	condition:
		any of ($a_*)
 
}