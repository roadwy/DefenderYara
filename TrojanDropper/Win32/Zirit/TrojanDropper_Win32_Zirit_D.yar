
rule TrojanDropper_Win32_Zirit_D{
	meta:
		description = "TrojanDropper:Win32/Zirit.D,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {47 81 ff d0 07 00 00 7c c2 6a 00 e8 ?? ?? 00 00 8b 54 24 14 83 c4 04 2b c2 3d 60 54 00 00 89 44 24 10 73 79 6a 00 e8 ?? ?? 00 00 99 b9 14 00 00 00 83 c4 04 f7 f9 52 ff d5 } //4
		$a_01_1 = {50 68 02 00 00 80 ff d6 ba 00 97 49 01 8b 44 24 10 8d 04 80 8d 04 80 8d 0c 80 c1 e1 03 2b d1 52 ff d5 } //4
		$a_00_2 = {61 6e 74 69 76 25 73 25 73 00 00 69 69 72 75 73 } //2 湡楴╶╳s椀物獵
		$a_00_3 = {4b 62 64 00 4d 6f 6e 00 57 69 6e 00 53 79 73 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*4+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}
rule TrojanDropper_Win32_Zirit_D_2{
	meta:
		description = "TrojanDropper:Win32/Zirit.D,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_00_0 = {0f 84 80 00 00 00 85 ff 76 18 83 ce ff 8d 43 01 2b f3 8a 0b 8a 10 32 d1 88 10 40 8d 14 06 3b d7 72 f0 } //8
		$a_02_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 6a 04 8d 85 ?? ?? ?? ?? 6a 00 50 ff 15 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 50 6a 00 6a 11 ff 15 ?? ?? ?? 00 85 c0 74 09 6a 00 50 ff 15 ?? ?? ?? 00 5f 5e 8b e5 5d c3 } //4
		$a_00_2 = {5c 49 6e 73 74 61 6c 6c 65 72 5c 7b 28 6e 75 6c 6c 29 7d 5c 41 76 70 52 75 6e 4f 6e 63 65 2e 64 6c 6c } //2 \Installer\{(null)}\AvpRunOnce.dll
		$a_00_3 = {3a 52 65 70 65 61 74 } //1 :Repeat
		$a_00_4 = {64 65 6c 20 22 25 73 22 } //1 del "%s"
		$a_00_5 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //1 if exist "%s" goto Repeat
		$a_00_6 = {5c 74 65 6d 70 64 65 6c 2e 62 61 74 } //1 \tempdel.bat
		$a_00_7 = {72 75 6e 64 6c 6c 33 32 20 22 25 73 22 2c 73 65 72 76 69 63 65 } //1 rundll32 "%s",service
		$a_00_8 = {25 73 5c 25 73 2e 64 6c 6c } //1 %s\%s.dll
		$a_00_9 = {41 70 70 45 76 65 6e 74 73 5c 53 63 68 65 6d 65 73 5c 41 70 70 73 5c 45 78 70 6c 6f 72 65 72 5c 4e 61 76 69 67 61 74 69 6e 67 } //1 AppEvents\Schemes\Apps\Explorer\Navigating
	condition:
		((#a_00_0  & 1)*8+(#a_02_1  & 1)*4+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=8
 
}