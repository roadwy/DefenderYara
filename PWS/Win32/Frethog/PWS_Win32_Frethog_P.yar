
rule PWS_Win32_Frethog_P{
	meta:
		description = "PWS:Win32/Frethog.P,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {78 79 75 70 72 69 25 64 2e 64 6c 6c } //01 00  xyupri%d.dll
		$a_01_1 = {43 5a 58 53 44 45 52 44 41 4b 53 54 58 4d 48 5f 4d 58 } //01 00  CZXSDERDAKSTXMH_MX
		$a_00_2 = {45 33 46 34 32 36 46 36 2d 34 32 41 35 2d 41 32 39 45 2d 38 36 33 34 2d 42 43 36 39 34 41 38 38 46 42 37 44 } //01 00  E3F426F6-42A5-A29E-8634-BC694A88FB7D
		$a_00_3 = {4d 00 4e 00 44 00 4c 00 4c 00 } //01 00  MNDLL
		$a_00_4 = {52 61 76 4d 6f 6e 2e 65 78 65 } //01 00  RavMon.exe
		$a_00_5 = {41 6c 65 72 74 44 69 61 6c 6f 67 } //01 00  AlertDialog
		$a_00_6 = {50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //00 00  Product_Notification
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Frethog_P_2{
	meta:
		description = "PWS:Win32/Frethog.P,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 78 74 72 20 72 69 73 69 6e 67 20 68 6f 6f 6b 20 4d 48 54 58 30 30 30 } //01 00  Extr rising hook MHTX000
		$a_00_1 = {45 33 46 34 32 36 46 36 2d 38 36 33 34 2d 34 32 41 35 2d 41 32 39 45 2d 42 43 36 39 34 41 38 38 46 42 37 44 } //01 00  E3F426F6-8634-42A5-A29E-BC694A88FB7D
		$a_00_2 = {43 5a 58 53 44 45 52 44 41 4b 53 54 58 4d 48 5f 25 64 } //01 00  CZXSDERDAKSTXMH_%d
		$a_00_3 = {46 6f 72 74 68 67 6f 65 72 } //01 00  Forthgoer
		$a_00_4 = {74 78 6f 74 78 2e 65 78 65 } //01 00  txotx.exe
		$a_00_5 = {6d 68 6d 61 69 6e 2e 64 6c 6c } //01 00  mhmain.dll
		$a_00_6 = {57 53 47 41 4d 45 } //01 00  WSGAME
		$a_00_7 = {67 70 77 64 5f 67 65 74 5f 70 77 64 5f 74 65 78 74 } //01 00  gpwd_get_pwd_text
		$a_00_8 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_9 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}