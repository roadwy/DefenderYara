
rule PWS_Win32_Lesword_A{
	meta:
		description = "PWS:Win32/Lesword.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 65 6c 73 77 6f 72 64 2e 65 78 65 } //01 00  %s\elsword.exe
		$a_01_1 = {5c 64 61 74 61 5c 6d 61 69 6c 73 6d 74 70 2e 64 6c 6c } //01 00  \data\mailsmtp.dll
		$a_01_2 = {47 61 6d 65 44 6c 6c 2e 64 6c 6c } //01 00  GameDll.dll
		$a_01_3 = {26 70 70 77 64 3d 25 73 26 6d 61 63 3d 25 73 26 6d 62 68 } //01 00  &ppwd=%s&mac=%s&mbh
		$a_03_4 = {74 14 8d 54 24 90 01 01 68 90 01 03 10 52 ff 15 90 01 03 10 85 c0 75 19 8b 44 24 90 01 01 50 6a 00 6a 01 ff d3 8b f0 6a 00 56 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}