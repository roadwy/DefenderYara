
rule PWS_Win32_Frethog_Y{
	meta:
		description = "PWS:Win32/Frethog.Y,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 68 65 6e 67 74 75 2e 64 61 74 } //01 00  zhengtu.dat
		$a_01_1 = {67 61 6d 65 63 6c 69 65 6e 74 2e 65 78 65 } //01 00  gameclient.exe
		$a_01_2 = {4c 61 54 61 50 53 } //01 00  LaTaPS
		$a_01_3 = {49 5a 4d 74 65 41 4b 5a 47 5b 47 4e 5c 74 } //01 00  IZMteAKZG[GN\t
		$a_01_4 = {41 46 4c 47 5f 5b 74 6b 5d 5a 5a 4d 46 5c 7e 4d 5a 5b 41 47 46 74 7a 7d 66 } //01 00  AFLG_[tk]ZZMF\~MZ[AGFtz}f
		$a_01_5 = {78 5a 47 4c 5d 4b 5c 77 66 47 5c 41 4e 41 4b 49 5c 41 47 46 } //01 00  xZGL]K\wfG\ANAKI\AGF
		$a_01_6 = {69 44 4d 5a 5c 6c 41 49 44 47 4f } //01 00  iDMZ\lAIDGO
		$a_01_7 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //00 00  CallNextHookEx
	condition:
		any of ($a_*)
 
}