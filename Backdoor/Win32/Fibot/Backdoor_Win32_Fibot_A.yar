
rule Backdoor_Win32_Fibot_A{
	meta:
		description = "Backdoor:Win32/Fibot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 6f 67 67 65 72 2f 70 6f 73 74 2e 70 68 70 3f 62 6f 74 5f 69 64 3d 25 73 26 63 6d 64 3d 25 73 } //1 /logger/post.php?bot_id=%s&cmd=%s
		$a_01_1 = {2f 6c 6f 67 67 65 72 2f 63 6f 6d 6d 61 6e 64 2e 70 68 70 3f 62 6f 74 5f 69 64 3d 25 73 26 6f 73 3d 25 73 26 68 6f 73 74 6e 61 6d 65 3d 25 73 26 74 69 6d 65 3d 25 73 } //1 /logger/command.php?bot_id=%s&os=%s&hostname=%s&time=%s
		$a_01_2 = {2f 6c 6f 67 67 65 72 2f 75 70 6c 6f 61 64 2e 70 68 70 3f 62 6f 74 5f 69 64 3d 25 73 26 63 6d 64 3d 25 73 26 70 61 74 68 3d 25 73 } //1 /logger/upload.php?bot_id=%s&cmd=%s&path=%s
		$a_01_3 = {34 32 2e 31 31 32 2e 32 39 2e 32 31 } //1 42.112.29.21
		$a_00_4 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 46 69 78 65 64 2e 65 78 65 } //1 C:\Users\%s\AppData\Local\Temp\Fixed.exe
		$a_00_5 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 25 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 46 69 78 65 64 2e 65 78 65 } //1 C:\Documents and Settings\%s\Application Data\Fixed.exe
		$a_00_6 = {63 6c 69 72 65 73 75 6c 74 2e 74 78 74 } //1 cliresult.txt
		$a_00_7 = {42 6f 74 20 69 6e 73 74 61 6c 6c 20 73 75 63 63 65 73 73 } //1 Bot install success
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}