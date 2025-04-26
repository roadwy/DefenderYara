
rule PWS_Win32_OnLineGames{
	meta:
		description = "PWS:Win32/OnLineGames,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 0e f3 ab 66 ab aa 59 33 c0 8d bd ?? ff ff ff 88 9d ?? ff ff ff f3 ab 66 ab c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 31 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 31 c6 05 ?? ?? ?? ?? 32 } //1
		$a_01_1 = {2f 64 61 74 61 2f 63 6f 75 6e 74 2e 61 73 70 3f 75 3d 25 73 } //1 /data/count.asp?u=%s
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule PWS_Win32_OnLineGames_2{
	meta:
		description = "PWS:Win32/OnLineGames,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 85 e4 fb ff ff 50 e8 ?? ?? ff ff 68 00 02 00 00 8d 85 ec fd ff ff 50 e8 ?? ?? ff ff 68 04 01 00 00 8d 85 e8 fc ff ff 50 e8 ?? ?? ff ff 6a 05 68 } //1
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6b 6e 6c 45 78 74 2e 64 6c 6c } //1 C:\WINDOWS\SYSTEM32\knlExt.dll
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 44 72 69 76 65 72 73 5c 75 73 62 4b 65 79 49 6e 69 74 2e 73 79 73 } //1 C:\WINDOWS\SYSTEM32\Drivers\usbKeyInit.sys
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule PWS_Win32_OnLineGames_3{
	meta:
		description = "PWS:Win32/OnLineGames,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {9c fb 12 00 a4 fc 12 00 89 10 40 00 00 00 e4 77 b8 ff 12 00 95 7b 41 00 00 00 00 00 bf 7b 41 00 26 00 00 00 b8 ff 12 00 c8 7b 41 00 a4 fd 12 00 00 00 00 00 00 00 00 00 00 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 44 72 69 76 65 72 73 5c 75 73 62 4b 65 79 49 6e 69 74 2e 73 79 73 00 00 00 00 00 00 00 00 00 00 } //1
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6b 6e 6c 45 78 74 2e 64 6c 6c } //1 C:\WINDOWS\SYSTEM32\knlExt.dll
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}