
rule TrojanDropper_Win32_Perkesh_B{
	meta:
		description = "TrojanDropper:Win32/Perkesh.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 00 6a 00 6a 02 6a 00 6a 01 68 00 00 00 c0 50 e8 } //01 00 
		$a_02_1 = {68 3f 00 0f 00 6a 00 6a 00 e8 90 01 04 89 45 ec 33 c0 55 68 90 01 03 00 64 ff 30 64 89 20 83 7d ec 00 74 75 6a 00 6a 00 6a 00 6a 00 6a 00 53 6a 00 6a 03 6a 01 6a 30 90 02 20 3d 31 04 00 00 90 00 } //01 00 
		$a_00_2 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 46 6f 6e 74 73 5c } //01 00  %systemroot%\Fonts\
		$a_00_3 = {55 70 61 63 6b 42 79 44 77 69 6e 67 40 } //00 00  UpackByDwing@
	condition:
		any of ($a_*)
 
}