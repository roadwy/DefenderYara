
rule PWS_Win32_OnLineGames_CQC{
	meta:
		description = "PWS:Win32/OnLineGames.CQC,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_00_1 = {61 64 64 72 25 73 68 65 6c 70 } //1 addr%shelp
		$a_00_2 = {00 67 61 6d 65 2e 65 78 65 } //1
		$a_00_3 = {71 64 73 68 6d 2e 64 6c 6c } //1 qdshm.dll
		$a_02_4 = {b0 65 c6 45 ?? 61 88 45 ?? 88 45 ?? 8d 45 ?? c6 45 ?? 76 50 c6 45 ?? 70 c6 45 ?? 2e c6 45 ?? 78 c6 45 ?? 00 } //2
		$a_02_5 = {03 2f c6 45 ?? 63 c6 45 ?? 64 c6 45 ?? 65 c6 45 ?? 6c } //2
		$a_00_6 = {8b d2 90 8b d2 90 8b d2 90 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*2+(#a_02_5  & 1)*2+(#a_00_6  & 1)*1) >=13
 
}