
rule Worm_Win32_Soulclose_A{
	meta:
		description = "Worm:Win32/Soulclose.A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe6 00 ffffffe6 00 16 00 00 64 00 "
		
	strings :
		$a_00_0 = {4f 00 70 00 65 00 6e 00 59 00 6f 00 75 00 72 00 53 00 6f 00 75 00 6c 00 } //0a 00  OpenYourSoul
		$a_01_1 = {20 00 67 00 6f 00 74 00 6f 00 20 00 67 00 6d 00 } //0a 00   goto gm
		$a_00_2 = {20 00 67 00 6f 00 74 00 6f 00 20 00 6b 00 69 00 6c 00 6c 00 } //0a 00   goto kill
		$a_00_3 = {6b 00 69 00 6c 00 6c 00 2e 00 62 00 61 00 74 00 } //0a 00  kill.bat
		$a_00_4 = {3a 00 6b 00 69 00 6c 00 6c 00 } //0a 00  :kill
		$a_00_5 = {20 00 67 00 6f 00 74 00 6f 00 20 00 72 00 65 00 64 00 65 00 6c 00 } //0a 00   goto redel
		$a_00_6 = {6f 00 70 00 65 00 6e 00 3d 00 63 00 66 00 2e 00 65 00 78 00 65 00 } //0a 00  open=cf.exe
		$a_00_7 = {3a 00 72 00 65 00 64 00 65 00 6c 00 } //0a 00  :redel
		$a_01_8 = {4f 6e 44 3d 61 } //0a 00  OnD=a
		$a_00_9 = {63 00 66 00 2e 00 65 00 78 00 65 00 } //0a 00  cf.exe
		$a_00_10 = {2e 00 65 00 78 00 65 00 2e 00 65 00 78 00 65 00 } //05 00  .exe.exe
		$a_01_11 = {25 2e 30 59 4a 25 } //05 00  %.0YJ%
		$a_01_12 = {6c 6c 46 5c 25 69 2e 51 } //05 00  llF\%i.Q
		$a_00_13 = {64 00 65 00 6c 00 20 00 25 00 30 00 } //05 00  del %0
		$a_00_14 = {76 00 6d 00 6d 00 72 00 65 00 67 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00  vmmreg32.exe
		$a_00_15 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 } //01 00  [AutoRun]
		$a_00_16 = {69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 } //01 00  if exist 
		$a_00_17 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //02 00  autorun.inf
		$a_00_18 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 } //02 00  avp.exe
		$a_00_19 = {31 00 2e 00 76 00 62 00 70 00 } //01 00  1.vbp
		$a_01_20 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //02 00  GetTempPathA
		$a_00_21 = {41 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 } //00 00  A*\AC:\Documents and Settings\
	condition:
		any of ($a_*)
 
}