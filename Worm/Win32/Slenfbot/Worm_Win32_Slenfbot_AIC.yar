
rule Worm_Win32_Slenfbot_AIC{
	meta:
		description = "Worm:Win32/Slenfbot.AIC,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 41 } //01 00  GetLogicalDriveStringsA
		$a_01_1 = {23 62 6f 74 76 35 2e 65 78 65 7c 44 7c 4d 65 6d 6f 72 79 20 45 78 65 63 75 74 65 7c 25 74 68 69 73 65 78 65 25 23 46 69 6c 65 49 6e 66 6f 2e 77 68 6f 7c 54 7c 45 78 74 72 61 63 74 20 46 69 6c 65 20 4f 6e 6c 79 7c 4e 6f 6e 65 20 49 6e 6a 65 63 74 } //01 00  #botv5.exe|D|Memory Execute|%thisexe%#FileInfo.who|T|Extract File Only|None Inject
		$a_01_2 = {00 74 65 61 6c 74 68 53 65 74 74 69 6e 67 73 00 55 73 62 00 70 32 70 53 70 4d 61 73 6f 6e 00 } //01 00 
		$a_01_3 = {5c 00 65 00 4d 00 75 00 6c 00 65 00 5c 00 49 00 6e 00 63 00 6f 00 6d 00 69 00 6e 00 67 00 5c 00 } //00 00  \eMule\Incoming\
	condition:
		any of ($a_*)
 
}