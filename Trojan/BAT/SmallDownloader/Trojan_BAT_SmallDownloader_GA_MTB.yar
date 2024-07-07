
rule Trojan_BAT_SmallDownloader_GA_MTB{
	meta:
		description = "Trojan:BAT/SmallDownloader.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 0b 00 00 "
		
	strings :
		$a_80_0 = {2f 63 20 64 69 72 20 43 3a 5c 20 3e 25 54 45 4d 50 25 5c 64 69 72 2e 74 78 74 } ///c dir C:\ >%TEMP%\dir.txt  1
		$a_80_1 = {74 68 65 20 70 72 6f 63 65 73 73 20 69 73 20 65 6e 64 65 64 } //the process is ended  1
		$a_80_2 = {45 72 72 6f 72 20 7b 30 7d 3a 20 7b 31 7d } //Error {0}: {1}  1
		$a_80_3 = {57 69 6e 53 74 61 30 5c } //WinSta0\  1
		$a_80_4 = {69 70 6c 6f 67 67 65 72 2e 6f 72 67 2f } //iplogger.org/  1
		$a_80_5 = {68 74 74 70 3a 2f 2f } //http://  1
		$a_80_6 = {7c 20 4f 53 3a } //| OS:  1
		$a_80_7 = {7c 20 4e 61 6d 65 3a } //| Name:  1
		$a_80_8 = {43 50 55 3a } //CPU:  1
		$a_80_9 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0  1
		$a_80_10 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 43 6f 6d 70 75 74 65 72 4e 61 6d 65 5c 43 6f 6d 70 75 74 65 72 4e 61 6d 65 } //HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=10
 
}