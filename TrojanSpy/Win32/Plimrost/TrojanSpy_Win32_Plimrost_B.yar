
rule TrojanSpy_Win32_Plimrost_B{
	meta:
		description = "TrojanSpy:Win32/Plimrost.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 00 61 00 72 00 64 00 43 00 6f 00 72 00 65 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 46 00 6f 00 72 00 20 00 3a 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 } //01 00  HardCore Software For : Public
		$a_00_1 = {3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 64 00 64 00 26 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 } //01 00  ?action=add&username=
		$a_03_2 = {f4 02 a9 e7 0b 90 01 04 23 90 01 02 2a 31 90 01 02 32 04 00 90 01 04 35 90 01 02 04 90 01 02 64 72 ff 10 00 90 00 } //01 00 
		$a_03_3 = {f4 3e eb 6e 90 01 02 b3 fb e6 e5 70 90 01 02 35 90 01 02 6b 90 01 02 f4 1a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}