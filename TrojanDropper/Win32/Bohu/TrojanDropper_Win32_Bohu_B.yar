
rule TrojanDropper_Win32_Bohu_B{
	meta:
		description = "TrojanDropper:Win32/Bohu.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {81 38 4e 43 52 43 75 0e 8a 48 04 80 c9 20 80 f9 20 75 03 83 ce 04 81 78 fe 20 2f 44 3d } //01 00 
		$a_02_1 = {75 6e 63 6f 6d 70 72 65 73 73 20 2d 73 20 90 01 05 2e 78 6d 6c 20 2d 64 90 00 } //01 00 
		$a_02_2 = {2f 54 49 4d 45 4f 55 54 3d 90 01 01 30 30 30 30 00 45 78 65 63 54 6f 4c 6f 67 90 00 } //01 00 
		$a_00_3 = {73 76 72 2e 61 73 70 3f 74 3d 75 75 70 6c 61 79 26 75 3d } //00 00  svr.asp?t=uuplay&u=
	condition:
		any of ($a_*)
 
}