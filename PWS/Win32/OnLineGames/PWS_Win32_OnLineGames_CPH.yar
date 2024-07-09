
rule PWS_Win32_OnLineGames_CPH{
	meta:
		description = "PWS:Win32/OnLineGames.CPH,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 76 70 2e 65 78 65 } //1 avp.exe
		$a_00_1 = {77 6f 77 2e 65 78 65 } //1 wow.exe
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_3 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_02_4 = {55 8b ec 81 ec ?? ?? 00 00 53 8b d2 8b c0 90 90 8b d2 90 90 8b db 90 90 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*3) >=7
 
}