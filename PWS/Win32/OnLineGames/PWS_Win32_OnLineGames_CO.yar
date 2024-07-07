
rule PWS_Win32_OnLineGames_CO{
	meta:
		description = "PWS:Win32/OnLineGames.CO,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {67 61 6d 65 2d 72 32 } //1 game-r2
		$a_01_1 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 drivers\etc\hosts
		$a_01_2 = {32 32 32 2e 37 33 2e 31 30 2e 38 34 20 20 20 20 77 77 77 2e 67 61 6d 65 2d 72 32 2e 63 6f 6d } //1 222.73.10.84    www.game-r2.com
		$a_01_3 = {63 76 2e 62 61 74 } //1 cv.bat
		$a_01_4 = {64 65 6c 20 25 30 } //1 del %0
		$a_01_5 = {38 46 36 32 43 31 34 38 2d 32 39 33 37 2d 34 46 36 30 2d 39 37 31 44 2d 44 36 41 39 35 34 37 42 31 39 43 33 } //1 8F62C148-2937-4F60-971D-D6A9547B19C3
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}