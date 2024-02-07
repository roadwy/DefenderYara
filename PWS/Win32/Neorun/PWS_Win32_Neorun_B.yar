
rule PWS_Win32_Neorun_B{
	meta:
		description = "PWS:Win32/Neorun.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 79 52 65 61 6c 57 6f 72 6b } //01 00  MyRealWork
		$a_81_1 = {52 75 6e 50 72 6f 63 65 73 73 } //01 00  RunProcess
		$a_81_2 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 } //01 00  WinSta0\Default
		$a_81_3 = {57 6f 72 6b 52 75 6e 54 68 72 65 61 64 } //01 00  WorkRunThread
		$a_81_4 = {61 62 65 32 38 36 39 66 2d 39 62 34 37 2d 34 63 64 39 2d 61 33 35 38 2d 63 32 32 39 30 34 64 62 61 37 66 37 } //01 00  abe2869f-9b47-4cd9-a358-c22904dba7f7
		$a_01_5 = {4e 00 65 00 6f 00 2c 00 77 00 65 00 6c 00 63 00 6f 00 6d 00 65 00 20 00 74 00 6f 00 20 00 74 00 68 00 65 00 20 00 64 00 65 00 73 00 65 00 72 00 74 00 20 00 6f 00 66 00 20 00 72 00 65 00 61 00 6c 00 2e 00 } //00 00  Neo,welcome to the desert of real.
	condition:
		any of ($a_*)
 
}