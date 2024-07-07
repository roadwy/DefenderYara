
rule TrojanSpy_Win32_Shiotob_D_bit{
	meta:
		description = "TrojanSpy:Win32/Shiotob.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {2d 75 70 64 61 74 65 } //1 -update
		$a_01_1 = {2d 61 75 74 6f 72 75 6e } //1 -autorun
		$a_01_2 = {26 69 70 63 6e 66 3d 00 26 73 63 6b 70 6f 72 74 3d 00 } //1 椦捰普=猦正潰瑲=
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_03_4 = {88 c3 32 1c 0a c1 e8 08 33 04 9d 90 01 04 41 75 ee 90 00 } //5
		$a_03_5 = {83 45 fc 04 81 6d f0 90 01 04 8b 45 90 01 01 8b 55 90 01 01 31 10 ff 45 90 01 01 ff 4d 90 01 01 75 e5 90 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*5+(#a_03_5  & 1)*5) >=13
 
}