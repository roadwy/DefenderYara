
rule TrojanSpy_Win32_Gamker_A_dll{
	meta:
		description = "TrojanSpy:Win32/Gamker.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {62 6f 74 69 64 3d 25 73 26 76 65 72 3d [0-08] 26 75 70 3d 25 75 26 6f 73 3d 25 30 33 75 26 6c 74 69 6d 65 3d 25 73 25 64 26 74 6f 6b 65 6e 3d 25 64 26 63 6e 3d 74 65 73 74 78 26 61 76 3d 25 73 } //1
		$a_01_1 = {42 55 48 7c 42 41 4e 4b 7c 41 43 43 4f 55 4e 54 7c 43 41 53 48 7c 4b 41 53 53 41 7c 44 49 52 45 4b 7c 46 49 4e 41 4e 7c 4f 50 45 52 7c 46 49 4e 4f 54 44 45 4c 7c 44 49 52 45 43 54 7c 52 4f 53 50 49 4c } //1 BUH|BANK|ACCOUNT|CASH|KASSA|DIREK|FINAN|OPER|FINOTDEL|DIRECT|ROSPIL
		$a_01_2 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 7c 6f 70 65 72 61 2e 65 78 65 7c 66 69 72 65 66 6f 78 2e 65 78 65 7c 63 68 72 6f 6d 65 2e 65 78 65 7c 6d 61 78 74 68 6f 6e 2e 65 78 65 7c 6a 61 76 61 2e 65 78 65 } //1 iexplore.exe|opera.exe|firefox.exe|chrome.exe|maxthon.exe|java.exe
		$a_01_3 = {2f 67 69 74 68 75 62 2e 70 68 70 00 5f 30 78 25 30 38 78 00 2e 74 6d 70 } //1
		$a_03_4 = {0f b6 5d 0f 88 1f 0f b6 5d 0f 0f b6 7d 0b 03 fb 8a 5d ff 81 e7 ff 00 00 00 32 1c 07 fe c1 88 88 00 01 00 00 88 90 ?? 00 00 88 1e 46 ff 4d f8 75 90 90 } //1
		$a_03_5 = {75 2d b8 02 00 00 00 e8 dc 46 00 00 85 c0 74 15 33 c9 80 38 31 8b f0 0f 94 c1 89 0d 94 c0 05 10 e8 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 3d ?? ?? ?? ?? ?? ?? 75 6c 85 db 75 4f 33 f6 39 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}