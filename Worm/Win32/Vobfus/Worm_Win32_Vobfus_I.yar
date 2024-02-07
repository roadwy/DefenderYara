
rule Worm_Win32_Vobfus_I{
	meta:
		description = "Worm:Win32/Vobfus.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {27 58 ff 0a 25 00 04 00 35 58 ff 00 14 f5 01 00 00 00 fb fe 23 54 ff 0a 00 00 04 00 2f 54 ff 00 0b f4 01 f4 01 0a 01 00 08 00 00 28 f5 01 00 00 00 fb fe 23 50 ff f5 01 00 00 00 fb fe 23 54 ff 04 58 ff 0a 02 00 0c 00 32 04 00 54 ff 50 ff 35 58 ff 00 25 f5 00 00 00 00 f5 00 00 00 00 04 4c ff 05 03 00 24 04 00 0d 14 00 05 00 08 4c ff 0d 38 01 06 00 1a 4c ff } //01 00 
		$a_00_1 = {56 42 2e 44 72 69 76 65 4c 69 73 74 42 6f 78 } //01 00  VB.DriveListBox
		$a_00_2 = {00 77 73 6f 63 6b 33 32 00 0e 00 00 00 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 00 } //01 00 
		$a_01_3 = {a9 f3 00 01 c1 e7 04 60 ff 9d fb 12 fc 0d } //00 00 
	condition:
		any of ($a_*)
 
}