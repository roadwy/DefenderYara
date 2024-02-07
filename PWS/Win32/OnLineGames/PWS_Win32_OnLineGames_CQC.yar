
rule PWS_Win32_OnLineGames_CQC{
	meta:
		description = "PWS:Win32/OnLineGames.CQC,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_1 = {61 64 64 72 25 73 68 65 6c 70 } //01 00  addr%shelp
		$a_00_2 = {00 67 61 6d 65 2e 65 78 65 } //01 00 
		$a_00_3 = {71 64 73 68 6d 2e 64 6c 6c } //02 00  qdshm.dll
		$a_02_4 = {b0 65 c6 45 90 01 01 61 88 45 90 01 01 88 45 90 01 01 8d 45 90 01 01 c6 45 90 01 01 76 50 c6 45 90 01 01 70 c6 45 90 01 01 2e c6 45 90 01 01 78 c6 45 90 01 01 00 90 00 } //02 00 
		$a_02_5 = {03 2f c6 45 90 01 01 63 c6 45 90 01 01 64 c6 45 90 01 01 65 c6 45 90 01 01 6c 90 00 } //01 00 
		$a_00_6 = {8b d2 90 8b d2 90 8b d2 90 } //00 00 
	condition:
		any of ($a_*)
 
}