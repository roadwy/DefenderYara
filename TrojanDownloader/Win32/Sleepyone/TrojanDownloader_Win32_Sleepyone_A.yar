
rule TrojanDownloader_Win32_Sleepyone_A{
	meta:
		description = "TrojanDownloader:Win32/Sleepyone.A,SIGNATURE_TYPE_PEHSTR_EXT,60 09 ffffff98 08 0b 00 00 "
		
	strings :
		$a_00_0 = {40 45 43 48 4f 20 4f 46 46 0d 0a 3e 20 74 65 6d 70 2e 72 65 67 20 45 43 48 4f 20 52 45 47 45 44 49 54 34 0d 0a 3e 3e 20 74 65 6d 70 2e 72 65 67 20 45 43 48 4f 2e 0d 0a 3e 3e 20 74 65 6d 70 2e 72 65 67 20 45 43 48 4f 20 5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5d 0d 0a 3e 3e 20 74 65 6d 70 2e 72 65 67 20 45 43 48 4f 20 22 53 68 65 6c 6c 22 3d 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1000
		$a_02_1 = {6a 00 6a 00 6a 00 8d 45 e4 b9 ?? ?? 41 00 8b 15 ?? ?? 41 00 e8 ?? ?? ff ff 8b 45 e4 e8 ?? ?? ff ff 50 68 ?? ?? 41 00 6a 00 e8 } //1000
		$a_00_2 = {61 64 64 20 68 6b 6c 6d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 20 2f 76 20 73 65 72 76 69 63 65 73 20 2f 64 } //1000 add hklm\software\microsoft\windows\currentversion\run /v services /d
		$a_02_3 = {8d 45 c4 ba 03 00 00 00 e8 ?? ?? ff ff 8b 45 c4 e8 ?? ?? ff ff 50 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 } //1000
		$a_02_4 = {77 69 6e 64 6f 77 73 ?? 73 65 72 76 69 63 65 73 2e 65 78 65 } //100
		$a_02_5 = {77 69 6e 64 6f 77 73 ?? 75 73 65 72 69 6e 69 74 2e 65 78 65 } //100
		$a_00_6 = {53 54 41 52 54 20 2f 57 41 49 54 20 52 45 47 45 44 49 54 20 2f 53 20 74 65 6d 70 2e 72 65 67 } //100 START /WAIT REGEDIT /S temp.reg
		$a_00_7 = {3a 5c 77 69 6e 64 6f 77 73 5c 73 65 72 76 69 63 65 73 2e 65 78 65 20 2f 66 } //100 :\windows\services.exe /f
		$a_00_8 = {44 45 4c 20 74 65 6d 70 2e 72 65 67 } //100 DEL temp.reg
		$a_00_9 = {72 65 67 00 6f 70 65 6e 00 } //100
		$a_00_10 = {63 3a 5c 78 2e 65 78 65 } //100 c:\x.exe
	condition:
		((#a_00_0  & 1)*1000+(#a_02_1  & 1)*1000+(#a_00_2  & 1)*1000+(#a_02_3  & 1)*1000+(#a_02_4  & 1)*100+(#a_02_5  & 1)*100+(#a_00_6  & 1)*100+(#a_00_7  & 1)*100+(#a_00_8  & 1)*100+(#a_00_9  & 1)*100+(#a_00_10  & 1)*100) >=2200
 
}