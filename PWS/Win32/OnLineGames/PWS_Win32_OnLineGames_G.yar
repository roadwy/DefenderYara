
rule PWS_Win32_OnLineGames_G{
	meta:
		description = "PWS:Win32/OnLineGames.G,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 2e 73 79 73 } //1 kill.sys
		$a_00_1 = {67 72 6f 75 70 2e 69 6e 69 } //1 group.ini
		$a_00_2 = {63 73 72 73 73 2e 65 78 65 } //1 csrss.exe
		$a_00_3 = {6d 69 72 31 2e 64 61 74 } //1 mir1.dat
		$a_00_4 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_00_6 = {55 8b ec 8b 45 0c 53 83 f8 01 0f 85 b9 01 00 00 90 8b d2 8b c0 90 8b d2 90 8b db 90 8b c9 90 90 8b d2 8b c0 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*10) >=16
 
}
rule PWS_Win32_OnLineGames_G_2{
	meta:
		description = "PWS:Win32/OnLineGames.G,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 64 64 72 25 73 68 65 6c 70 } //1 addr%shelp
		$a_00_1 = {71 64 73 68 6d 2e 64 6c 6c } //1 qdshm.dll
		$a_01_2 = {55 75 69 64 43 72 65 61 74 65 } //1 UuidCreate
		$a_01_3 = {57 53 43 57 72 69 74 65 50 72 6f 76 69 64 65 72 4f 72 64 65 72 } //1 WSCWriteProviderOrder
		$a_00_4 = {55 8b ec 81 ec 3c 06 00 00 53 90 8b d2 8b c0 90 8b d2 90 8b db 90 8b c9 90 90 8b d2 8b c0 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*10) >=14
 
}