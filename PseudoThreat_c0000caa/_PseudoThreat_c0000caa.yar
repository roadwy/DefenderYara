
rule _PseudoThreat_c0000caa{
	meta:
		description = "!PseudoThreat_c0000caa,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 19 00 0d 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //2 Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 61 72 65 64 54 61 73 6b 53 63 68 65 64 75 6c 65 72 } //2 Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 53 79 73 74 65 6d 20 41 6c 65 72 74 20 50 6f 70 75 70 } //5 Software\Microsoft\Windows\CurrentVersion\Uninstall\System Alert Popup
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c } //2 Software\Microsoft\Windows\CurrentVersion\Uninstall
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 57 69 6e 64 6f 77 73 58 70 32 30 30 33 } //2 Software\MicrosoftWindowsXp2003
		$a_02_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-08] 2e 64 6c 6c 2c 77 69 6e 64 6f 77 73 } //5
		$a_00_6 = {25 73 20 2f 64 65 6c 32 } //2 %s /del2
		$a_00_7 = {53 59 53 52 45 53 } //2 SYSRES
		$a_00_8 = {45 61 63 68 20 70 72 6f 63 65 73 73 20 68 61 73 20 61 6e 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 62 6c 6f 63 6b 20 61 73 73 6f 63 69 61 74 65 64 20 77 69 74 68 20 69 74 2e 20 54 68 65 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 62 6c 6f 63 6b 20 63 6f 6e 73 69 73 74 73 20 6f 66 20 61 20 6e 75 6c 6c 2d 74 65 72 6d 69 6e 61 74 65 64 20 62 6c 6f 63 6b 20 6f 66 20 6e 75 6c 6c 2d 74 65 72 6d 69 6e 61 74 65 64 20 73 74 72 69 6e 67 73 20 28 6d 65 61 6e 69 6e 67 20 74 68 65 72 65 20 61 72 65 20 74 77 6f 20 6e 75 6c 6c 20 62 79 74 65 73 20 61 74 20 74 68 65 20 65 6e 64 20 6f 66 20 74 68 65 20 62 6c 6f 63 6b 29 2c 20 77 68 65 72 65 20 65 61 63 68 20 73 74 72 69 6e 67 20 69 73 20 69 6e 20 74 68 65 20 66 6f 72 6d 3a } //5 Each process has an environment block associated with it. The environment block consists of a null-terminated block of null-terminated strings (meaning there are two null bytes at the end of the block), where each string is in the form:
		$a_00_9 = {77 69 6e 64 6f 77 73 20 78 70 20 61 6d 69 67 6f 20 79 6f 20 6d 61 6e 20 66 72 69 65 6e 64 73 20 68 65 6c 6c 6f 20 67 6f 2d 67 6f } //5 windows xp amigo yo man friends hello go-go
		$a_00_10 = {45 72 72 6f 72 20 4c 6f 61 64 20 68 44 65 6c 65 74 65 } //2 Error Load hDelete
		$a_00_11 = {25 73 5c 68 69 67 65 68 73 67 2e 64 6c 6c } //2 %s\higehsg.dll
		$a_00_12 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 6d 73 67 2e 64 6c 6c } //2 c:\windows\sysmsg.dll
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*5+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_02_5  & 1)*5+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*5+(#a_00_9  & 1)*5+(#a_00_10  & 1)*2+(#a_00_11  & 1)*2+(#a_00_12  & 1)*2) >=25
 
}