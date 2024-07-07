
rule Ransom_Win32_Hatecrypt{
	meta:
		description = "Ransom:Win32/Hatecrypt,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {64 65 61 74 68 2e 62 61 74 22 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 61 66 6f 6c 64 65 72 5c 64 65 61 74 68 2e 62 61 74 22 } //2 death.bat" del "C:\TEMP\afolder\death.bat"
		$a_01_1 = {64 65 61 74 68 6e 6f 74 65 2e 62 61 74 22 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 61 66 6f 6c 64 65 72 5c 64 65 61 74 68 6e 6f 74 65 2e 62 61 74 22 } //2 deathnote.bat" del "C:\TEMP\afolder\deathnote.bat"
		$a_01_2 = {57 49 46 49 2d 43 4f 4e 4e 45 43 54 2e 62 61 74 22 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 61 66 6f 6c 64 65 72 5c 57 49 46 49 2d 43 4f 4e 4e 45 43 54 2e 62 61 74 22 } //2 WIFI-CONNECT.bat" del "C:\TEMP\afolder\WIFI-CONNECT.bat"
		$a_01_3 = {77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 2e 62 61 74 22 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 61 66 6f 6c 64 65 72 5c 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 2e 62 61 74 22 } //2 windows defender.bat" del "C:\TEMP\afolder\windows defender.bat"
		$a_01_4 = {57 49 46 49 2e 6c 6e 6b 22 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 61 66 6f 6c 64 65 72 5c 57 49 46 49 2e 6c 6e 6b 22 } //2 WIFI.lnk" del "C:\TEMP\afolder\WIFI.lnk"
		$a_01_5 = {57 49 4e 44 45 46 45 4e 44 2e 6c 6e 6b 22 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 61 66 6f 6c 64 65 72 5c 57 49 4e 44 45 46 45 4e 44 2e 6c 6e 6b 22 } //2 WINDEFEND.lnk" del "C:\TEMP\afolder\WINDEFEND.lnk"
		$a_01_6 = {64 65 61 74 68 2e 6c 6e 6b 22 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 61 66 6f 6c 64 65 72 5c 64 65 61 74 68 2e 6c 6e 6b 22 } //2 death.lnk" del "C:\TEMP\afolder\death.lnk"
		$a_01_7 = {64 65 61 74 68 6e 6f 74 65 2e 6c 6e 6b 22 20 64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 61 66 6f 6c 64 65 72 5c 64 65 61 74 68 6e 6f 74 65 2e 6c 6e 6b 22 } //2 deathnote.lnk" del "C:\TEMP\afolder\deathnote.lnk"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=14
 
}