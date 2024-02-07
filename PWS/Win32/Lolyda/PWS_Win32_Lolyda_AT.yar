
rule PWS_Win32_Lolyda_AT{
	meta:
		description = "PWS:Win32/Lolyda.AT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 44 24 10 8a 04 02 32 01 34 90 01 01 46 3b 74 24 14 88 01 7c dd 90 00 } //01 00 
		$a_01_1 = {c6 45 f8 e9 03 50 14 8d 45 f8 50 51 2b d1 } //01 00 
		$a_00_2 = {3f 41 3d 25 73 26 75 3d 25 73 26 63 3d 25 73 26 6d 62 3d 25 73 00 } //01 00  䄿┽♳㵵猥挦┽♳扭┽s
		$a_00_3 = {26 50 3d 25 73 26 50 49 4e 3d 25 73 26 } //01 00  &P=%s&PIN=%s&
		$a_01_4 = {20 5a c7 1a 9f 43 72 ca 37 33 77 c7 e0 c5 43 fb ff fa } //00 00 
	condition:
		any of ($a_*)
 
}