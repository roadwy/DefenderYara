
rule Worm_Win32_Spybot_BY{
	meta:
		description = "Worm:Win32/Spybot.BY,SIGNATURE_TYPE_PEHSTR,2c 00 2b 00 09 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 52 45 43 59 43 4c 45 52 5c 6d 73 63 6f 6e 66 69 67 33 32 2e 65 78 65 } //10 C:\RECYCLER\msconfig32.exe
		$a_01_1 = {42 6f 74 20 6b 69 6c 6c 65 64 20 61 6e 64 20 72 65 6d 6f 76 65 64 3a 20 25 73 20 28 70 69 64 3a 20 25 64 29 21 } //10 Bot killed and removed: %s (pid: %d)!
		$a_01_2 = {25 73 20 25 73 20 22 66 6f 25 64 2e 6e 65 74 22 20 22 6c 6f 6c 22 20 3a 25 73 } //10 %s %s "fo%d.net" "lol" :%s
		$a_01_3 = {50 61 74 63 68 69 6e 67 20 74 63 70 69 70 2e 73 79 73 } //5 Patching tcpip.sys
		$a_01_4 = {63 6d 64 20 2f 63 20 65 63 68 6f 20 6f 70 65 6e 20 25 73 20 25 64 20 3e 3e 20 69 6b 20 26 65 63 68 6f 20 75 73 65 72 20 25 73 20 25 73 20 3e 3e 20 69 6b 20 26 65 63 68 6f 20 62 69 6e 61 72 79 20 3e 3e 20 69 6b 20 26 65 63 68 6f 20 67 65 74 20 25 73 20 3e 3e 20 69 6b 20 26 65 63 68 6f 20 62 79 65 20 3e 3e 20 69 6b 20 26 66 74 70 20 2d 6e 20 2d 76 20 2d 73 3a 69 6b 20 26 64 65 6c 20 69 6b 20 26 25 73 20 26 65 78 69 74 } //5 cmd /c echo open %s %d >> ik &echo user %s %s >> ik &echo binary >> ik &echo get %s >> ik &echo bye >> ik &ftp -n -v -s:ik &del ik &%s &exit
		$a_01_5 = {53 63 61 6e 6e 69 6e 67 3a 20 25 73 2c 20 25 64 20 74 68 72 65 61 64 73 2e 20 53 63 61 6e 6e 69 6e 67 20 56 4e 43 73 } //1 Scanning: %s, %d threads. Scanning VNCs
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 5c 4d 69 63 72 6f 73 6f 66 74 5c 5c 57 69 6e 64 6f 77 73 5c 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 5c 52 75 6e } //1 Software\\Microsoft\\Windows\\CurrentVersion\\Run
		$a_01_7 = {53 59 53 54 45 4d 5c 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 5c 53 65 72 76 69 63 65 73 5c 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 5c 50 61 72 61 6d 65 74 65 72 73 5c 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 5c 4c 69 73 74 } //1 SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List
		$a_01_8 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //1 RegSetValueExA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=43
 
}