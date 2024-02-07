
rule PWS_Win32_Frethog_N{
	meta:
		description = "PWS:Win32/Frethog.N,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 5a 4d 74 65 41 4b 5a 47 5b 47 4e 5c 74 } //01 00  IZMteAKZG[GN\t
		$a_01_1 = {41 46 4c 47 5f 5b 74 6b 5d 5a 5a 4d 46 5c 7e 4d 5a 5b 41 47 46 74 7a 7d 66 } //01 00  AFLG_[tk]ZZMF\~MZ[AGFtz}f
		$a_01_2 = {78 5a 47 4c 5d 4b 5c 77 66 47 5c 41 4e 41 4b 49 5c 41 47 46 } //01 00  xZGL]K\wfG\ANAKI\AGF
		$a_01_3 = {69 44 4d 5a 5c 6c 41 49 44 47 4f } //01 00  iDMZ\lAIDGO
		$a_01_4 = {77 7a 68 65 6e 67 74 75 2e 64 61 74 } //01 00  wzhengtu.dat
		$a_01_5 = {71 71 67 61 6d 65 2e 65 78 65 } //01 00  qqgame.exe
		$a_01_6 = {71 71 2e 65 78 65 } //00 00  qq.exe
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Frethog_N_2{
	meta:
		description = "PWS:Win32/Frethog.N,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 5a 4d 74 65 41 4b 5a 47 5b 47 4e 5c 74 } //01 00  IZMteAKZG[GN\t
		$a_01_1 = {41 46 4c 47 5f 5b 74 6b 5d 5a 5a 4d 46 5c 7e 4d 5a 5b 41 47 46 74 7a 7d 66 } //01 00  AFLG_[tk]ZZMF\~MZ[AGFtz}f
		$a_01_2 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 67 } //01 00  AVP.AlertDialog
		$a_01_3 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //01 00  AVP.Product_Notification
		$a_01_4 = {75 70 78 64 6e 64 2e 64 6c 6c } //01 00  upxdnd.dll
		$a_01_5 = {35 31 33 34 33 32 38 31 } //00 00  51343281
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Frethog_N_3{
	meta:
		description = "PWS:Win32/Frethog.N,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 7a 68 65 6e 67 74 75 2e 64 61 74 } //01 00  wzhengtu.dat
		$a_01_1 = {71 71 67 61 6d 65 2e 65 78 65 } //01 00  qqgame.exe
		$a_01_2 = {71 71 2e 65 78 65 } //01 00  qq.exe
		$a_01_3 = {66 3d 75 70 74 } //01 00  f=upt
		$a_01_4 = {66 3d 6e 6f 74 } //01 00  f=not
		$a_01_5 = {66 3d 74 72 74 } //01 00  f=trt
		$a_01_6 = {66 3d 66 61 74 } //01 00  f=fat
		$a_01_7 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_8 = {25 73 3f 73 72 76 3d 25 73 26 69 64 3d 25 73 26 70 3d 25 73 26 73 3d 25 73 26 73 73 3d 25 73 26 6a 73 3d 25 73 26 67 6a 3d 25 73 26 64 6a 3d 25 64 26 79 7a 3d 25 64 26 6a 7a 3d 25 64 } //00 00  %s?srv=%s&id=%s&p=%s&s=%s&ss=%s&js=%s&gj=%s&dj=%d&yz=%d&jz=%d
	condition:
		any of ($a_*)
 
}