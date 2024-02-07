
rule Worm_Win32_SoulClose_CC_MTB{
	meta:
		description = "Worm:Win32/SoulClose.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 00 75 00 63 00 6b 00 50 00 48 00 47 00 } //01 00  fuckPHG
		$a_01_1 = {43 00 43 00 54 00 56 00 2e 00 65 00 78 00 65 00 } //01 00  CCTV.exe
		$a_01_2 = {6b 00 69 00 6c 00 6c 00 2e 00 62 00 61 00 74 00 } //01 00  kill.bat
		$a_01_3 = {63 00 66 00 2e 00 65 00 78 00 65 00 } //01 00  cf.exe
		$a_01_4 = {4f 00 70 00 65 00 6e 00 59 00 6f 00 75 00 72 00 53 00 6f 00 75 00 6c 00 } //01 00  OpenYourSoul
		$a_01_5 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //01 00  autorun.inf
		$a_01_6 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 } //01 00  [AutoRun]
		$a_01_7 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 } //00 00  avp.exe
	condition:
		any of ($a_*)
 
}