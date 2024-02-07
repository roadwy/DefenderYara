
rule Worm_Win32_Datheens_B{
	meta:
		description = "Worm:Win32/Datheens.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 44 65 61 74 68 2e 65 78 65 } //01 00  \Death.exe
		$a_01_1 = {2e 53 43 52 00 00 00 00 ff ff ff ff 04 00 } //01 00 
		$a_01_2 = {2e 48 54 4d 4c 00 00 00 ff ff ff ff 04 00 } //01 00 
		$a_01_3 = {2e 41 53 50 58 00 00 00 ff ff ff ff 1b 00 } //01 00 
		$a_01_4 = {77 69 64 74 68 3d 30 20 68 65 69 67 68 74 3d 30 3e 3c 2f 69 66 72 61 6d 65 3e } //01 00  width=0 height=0></iframe>
		$a_01_5 = {3c 69 66 72 61 6d 65 20 73 72 63 3d } //01 00  <iframe src=
		$a_01_6 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //00 00  GetSystemDirectoryA
	condition:
		any of ($a_*)
 
}