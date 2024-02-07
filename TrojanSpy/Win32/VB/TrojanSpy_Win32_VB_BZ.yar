
rule TrojanSpy_Win32_VB_BZ{
	meta:
		description = "TrojanSpy:Win32/VB.BZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 48 6f 6f 6b 00 6d 6f 64 4d 61 69 6e 00 6d 6f 64 50 72 6f 63 65 73 73 00 } //01 00 
		$a_00_1 = {2d 00 73 00 79 00 73 00 72 00 75 00 6e 00 } //01 00  -sysrun
		$a_01_2 = {7f 0c 00 f3 ff 7f c4 e7 f5 00 00 01 00 b2 7f 0c 00 f3 00 80 c4 f4 00 cb e7 f5 00 00 00 80 c4 c5 7f 10 00 f3 ff 7f c4 e7 7f 10 00 f3 00 80 c4 f4 00 cb e7 f5 00 80 00 00 c4 c5 c5 } //01 00 
		$a_01_3 = {3a 00 38 00 38 00 2f 00 70 00 36 00 2e 00 61 00 73 00 70 00 3f 00 4d 00 41 00 43 00 3d 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}