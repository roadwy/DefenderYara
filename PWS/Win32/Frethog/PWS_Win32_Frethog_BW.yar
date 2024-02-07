
rule PWS_Win32_Frethog_BW{
	meta:
		description = "PWS:Win32/Frethog.BW,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 48 6f 6f 6b 4f 66 66 00 48 6f 6f 6b 4f 6e } //0a 00 
		$a_00_1 = {41 63 63 65 70 74 3a 20 2a 2f 2a 00 48 54 54 50 2f 31 2e 30 } //01 00  捁散瑰›⼪*呈偔ㄯ〮
		$a_00_2 = {2f 63 68 64 2f 73 65 6e 64 6d 61 69 6c 2e 61 73 70 } //01 00  /chd/sendmail.asp
		$a_00_3 = {69 6e 66 5c 44 6c 6c 41 64 64 72 65 73 73 2e 69 6e 69 } //01 00  inf\DllAddress.ini
		$a_02_4 = {53 65 72 76 3d 90 02 0f 43 61 6e 6b 3d 90 02 0f 4c 65 76 65 3d 90 02 0f 4e 61 6d 65 3d 90 00 } //01 00 
		$a_02_5 = {4d 69 62 61 6f 3d 90 02 0f 43 68 61 6e 67 3d 90 02 0f 44 69 61 6e 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}