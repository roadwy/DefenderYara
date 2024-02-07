
rule Worm_Win32_Autorun_PP{
	meta:
		description = "Worm:Win32/Autorun.PP,SIGNATURE_TYPE_PEHSTR,37 01 37 01 08 00 00 64 00 "
		
	strings :
		$a_01_0 = {64 72 69 76 65 72 73 2f 6b 6c 69 66 2e 73 79 73 } //64 00  drivers/klif.sys
		$a_01_1 = {41 75 74 6f 52 75 6e 2e 69 6e 66 } //64 00  AutoRun.inf
		$a_01_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c 4d 53 49 4e 46 4f } //0a 00  Program Files\Common Files\Microsoft Shared\MSINFO
		$a_01_3 = {46 69 65 6c 65 57 61 79 2e 74 78 74 } //0a 00  FieleWay.txt
		$a_01_4 = {42 65 69 7a 68 75 } //01 00  Beizhu
		$a_01_5 = {63 6d 64 20 2f 63 20 64 61 74 65 20 31 39 38 31 2d 30 31 2d 31 32 } //01 00  cmd /c date 1981-01-12
		$a_01_6 = {63 6d 64 20 2f 63 20 65 72 61 73 65 20 2f 46 } //01 00  cmd /c erase /F
		$a_01_7 = {72 65 6a 6f 69 63 65 } //00 00  rejoice
	condition:
		any of ($a_*)
 
}