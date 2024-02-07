
rule Worm_Win32_Vercuser_C{
	meta:
		description = "Worm:Win32/Vercuser.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 54 73 44 76 25 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  %TsDv%\autorun.inf
		$a_01_1 = {5b 61 75 74 6f 72 75 6e 5d 41 43 54 49 4f 4e 3d 4f 70 65 6e 20 55 53 42 20 44 72 69 76 65 6f 70 65 6e 3d } //01 00  [autorun]ACTION=Open USB Driveopen=
		$a_01_2 = {66 69 6c 65 73 65 74 61 74 74 72 69 62 2c 20 2b 52 41 53 48 2c 20 25 54 73 44 76 25 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  filesetattrib, +RASH, %TsDv%\autorun.inf
		$a_01_3 = {44 72 69 76 65 47 65 74 2c 20 52 6d 44 72 76 73 2c 20 6c 69 73 74 2c 20 52 45 4d 4f 56 41 42 4c 45 } //00 00  DriveGet, RmDrvs, list, REMOVABLE
	condition:
		any of ($a_*)
 
}