
rule Backdoor_Win32_Dumador{
	meta:
		description = "Backdoor:Win32/Dumador,SIGNATURE_TYPE_PEHSTR,0f 00 08 00 14 00 00 "
		
	strings :
		$a_01_0 = {5c 54 45 4d 50 5c 66 61 34 35 33 37 65 66 2e 74 6d 70 } //2 \TEMP\fa4537ef.tmp
		$a_01_1 = {3d 3d 3d 4b 45 59 4c 4f 47 47 45 52 20 44 41 54 41 20 45 4e 44 3d 3d 3d } //1 ===KEYLOGGER DATA END===
		$a_01_2 = {3d 3d 3d 4b 45 59 4c 4f 47 47 45 52 20 44 41 54 41 20 53 54 41 52 54 3d 3d 3d } //1 ===KEYLOGGER DATA START===
		$a_01_3 = {2a 2a 2a 20 50 72 6f 74 65 63 74 65 64 20 53 74 6f 72 61 67 65 20 44 61 74 61 20 2a 2a 2a } //1 *** Protected Storage Data ***
		$a_01_4 = {2a 2a 2a 20 50 72 6f 74 65 63 74 65 64 20 53 74 6f 72 61 67 65 20 44 61 74 61 20 65 6e 64 73 20 2a 2a 2a } //1 *** Protected Storage Data ends ***
		$a_01_5 = {64 72 77 78 72 77 78 72 77 78 20 31 20 30 20 20 20 20 20 20 20 20 20 40 64 69 73 6b 5f 58 } //2 drwxrwxrwx 1 0         @disk_X
		$a_01_6 = {5d 5c 64 76 70 2e 6c 6f 67 } //1 ]\dvp.log
		$a_01_7 = {6d 61 69 6c 73 65 6e 64 65 64 } //1 mailsended
		$a_01_8 = {3c 61 64 64 72 65 73 73 40 79 61 6e 64 65 78 2e 72 75 3e } //2 <address@yandex.ru>
		$a_01_9 = {73 6f 63 6b 73 2f 62 6f 74 2f 63 6d 64 2e 74 78 74 } //2 socks/bot/cmd.txt
		$a_01_10 = {5c 72 75 6e 64 6c 6c 6e 2e 73 79 73 } //1 \rundlln.sys
		$a_01_11 = {5c 54 45 4d 50 5c 66 65 34 33 65 37 30 31 2e 68 74 6d } //2 \TEMP\fe43e701.htm
		$a_01_12 = {2a 2a 2a 20 46 61 72 20 4d 61 6e 61 67 65 72 20 70 61 73 73 77 6f 72 64 73 20 2a 2a 2a } //2 *** Far Manager passwords ***
		$a_01_13 = {5b 57 65 62 4d 6f 6e 65 79 20 49 44 20 6c 69 73 74 5d } //2 [WebMoney ID list]
		$a_01_14 = {5b 46 61 72 20 4d 61 6e 61 67 65 72 20 70 61 73 73 77 6f 72 64 73 5d } //2 [Far Manager passwords]
		$a_01_15 = {5b 54 68 65 20 42 61 74 20 70 61 73 73 77 6f 72 64 73 5d } //2 [The Bat passwords]
		$a_01_16 = {5b 54 6f 74 61 6c 20 43 6f 6d 6d 61 6e 64 65 72 20 66 74 70 20 70 61 73 73 77 6f 72 64 73 5d } //2 [Total Commander ftp passwords]
		$a_01_17 = {5b 50 72 6f 74 65 63 74 65 64 20 53 74 6f 72 61 67 65 20 64 61 74 61 20 61 6c 72 65 61 64 79 20 73 65 6e 64 65 64 5d } //2 [Protected Storage data already sended]
		$a_01_18 = {3c 43 45 4e 54 45 52 3e 3c 42 3e 4b 65 79 73 20 65 6e 74 65 72 65 64 20 6f 6e 20 53 52 4b 20 4b 65 79 70 61 64 3c 2f 42 3e 3c 2f 43 45 4e 54 45 52 3e 3c 42 52 3e 3c 43 45 4e 54 45 52 3e } //2 <CENTER><B>Keys entered on SRK Keypad</B></CENTER><BR><CENTER>
		$a_01_19 = {5b 57 61 72 6e 69 6e 67 3a 20 74 68 65 20 6c 61 73 74 20 66 6f 72 6d 64 61 74 61 20 68 61 76 65 20 6f 6e 65 20 76 61 6c 69 64 20 74 61 6e 5d } //2 [Warning: the last formdata have one valid tan]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*1+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_01_13  & 1)*2+(#a_01_14  & 1)*2+(#a_01_15  & 1)*2+(#a_01_16  & 1)*2+(#a_01_17  & 1)*2+(#a_01_18  & 1)*2+(#a_01_19  & 1)*2) >=8
 
}