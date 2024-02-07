
rule Worm_Win32_Kasatall_A{
	meta:
		description = "Worm:Win32/Kasatall.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 41 53 53 4b 4b } //01 00  AASSKK
		$a_01_1 = {66 6f 6f 6f 6f 6c 2e 65 78 65 } //01 00  fooool.exe
		$a_01_2 = {5b 56 56 66 6c 61 67 52 75 6e 5d } //01 00  [VVflagRun]
		$a_01_3 = {44 3a 5c 44 61 74 61 2e 62 61 74 } //01 00  D:\Data.bat
		$a_01_4 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_5 = {46 6c 61 73 68 20 47 61 6d 65 20 32 30 30 37 5c 53 65 74 75 70 20 47 61 6d 65 2e 65 78 65 } //00 00  Flash Game 2007\Setup Game.exe
	condition:
		any of ($a_*)
 
}