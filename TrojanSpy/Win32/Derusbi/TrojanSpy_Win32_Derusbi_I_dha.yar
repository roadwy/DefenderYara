
rule TrojanSpy_Win32_Derusbi_I_dha{
	meta:
		description = "TrojanSpy:Win32/Derusbi.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 54 4c 4d 53 53 50 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 } //01 00 
		$a_00_1 = {72 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 61 00 75 00 64 00 00 00 } //01 00 
		$a_00_2 = {47 45 54 20 2f 50 68 6f 74 6f 73 2f 51 75 65 72 79 2e 63 67 69 3f 6c 6f 67 69 6e 69 64 3d } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}