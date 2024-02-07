
rule Worm_Win32_SillyShareCopy_T{
	meta:
		description = "Worm:Win32/SillyShareCopy.T,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 65 74 61 74 74 72 69 62 2c 2b 53 41 48 52 2c 25 74 6d 70 74 68 25 } //01 00  filesetattrib,+SAHR,%tmpth%
		$a_01_1 = {52 75 6e 2c 25 63 6f 6d 73 70 65 63 25 20 2f 63 20 65 63 68 6f 20 5b 61 75 74 6f 52 75 6e 5d } //01 00  Run,%comspec% /c echo [autoRun]
		$a_01_2 = {69 66 20 69 6e 66 6c 69 6e 65 20 21 3d 20 5b 61 75 74 6f 72 75 6e 5d } //01 00  if infline != [autorun]
		$a_01_3 = {66 69 6c 65 73 65 74 61 74 74 72 69 62 2c 2d 53 48 52 2c 45 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  filesetattrib,-SHR,E:\autorun.inf
		$a_01_4 = {23 73 69 6e 67 6c 65 69 6e 73 74 61 6e 63 65 2c 66 6f 72 63 65 } //01 00  #singleinstance,force
		$a_01_5 = {72 75 6e 2c 25 63 6f 6d 73 70 65 63 25 20 2f 63 20 74 73 6b 69 6c 6c 20 69 65 78 70 6c 6f 72 65 72 2c 2c 68 69 64 65 20 75 73 65 65 72 72 6f 72 6c 65 76 65 6c } //00 00  run,%comspec% /c tskill iexplorer,,hide useerrorlevel
	condition:
		any of ($a_*)
 
}