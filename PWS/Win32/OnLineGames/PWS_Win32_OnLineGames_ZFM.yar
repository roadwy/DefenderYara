
rule PWS_Win32_OnLineGames_ZFM{
	meta:
		description = "PWS:Win32/OnLineGames.ZFM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_02_0 = {51 6a 04 57 68 ?? ?? ?? ?? ff d5 85 c0 74 } //2
		$a_00_1 = {5c 6b 73 75 73 65 72 2e 64 6c 6c } //2 \ksuser.dll
		$a_00_2 = {c1 ee 00 00 } //1
		$a_00_3 = {c3 dc 00 00 } //1
		$a_00_4 = {53 65 63 75 72 69 74 79 4d 61 74 72 69 78 4b 65 79 70 61 64 42 75 74 74 6f 6e } //1 SecurityMatrixKeypadButton
		$a_00_5 = {53 65 63 75 72 69 74 79 4d 61 74 72 69 78 50 69 6e 77 68 65 65 6c 42 75 74 74 6f 6e } //1 SecurityMatrixPinwheelButton
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}
rule PWS_Win32_OnLineGames_ZFM_2{
	meta:
		description = "PWS:Win32/OnLineGames.ZFM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 4f 3c 83 c4 0c 03 cf 66 81 79 18 0b 01 75 ?? 66 8b 51 58 66 3b c2 1b db f7 db 03 da 66 8b 51 5a } //1
		$a_00_1 = {00 6b 73 75 73 65 72 2e 64 6c 6c 00 00 6d 69 64 69 6d 61 70 2e 64 6c 6c 00 63 6f 6d 72 65 73 2e 64 6c 6c 00 } //2
		$a_00_2 = {73 73 65 72 64 64 41 63 6f 72 50 74 65 47 } //1 sserddAcorPteG
		$a_00_3 = {25 73 2c 20 53 65 72 76 65 72 4d 61 69 6e 20 25 63 25 73 } //1 %s, ServerMain %c%s
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule PWS_Win32_OnLineGames_ZFM_3{
	meta:
		description = "PWS:Win32/OnLineGames.ZFM,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 64 61 74 61 2e 65 76 70 } //1 \data.evp
		$a_01_1 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_01_2 = {5c 64 6c 6c 63 61 63 68 65 5c 6c 70 6b 2e 64 6c 6c } //1 \dllcache\lpk.dll
		$a_01_3 = {64 65 6c 20 22 25 73 22 20 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 64 65 6c 65 74 65 } //1 del "%s" if exist "%s" goto delete
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}