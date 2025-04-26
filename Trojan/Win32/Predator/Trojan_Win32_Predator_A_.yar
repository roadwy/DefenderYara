
rule Trojan_Win32_Predator_A_{
	meta:
		description = "Trojan:Win32/Predator.A!!Predator.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {5c 63 66 74 70 5c 46 74 70 6c 69 73 74 2e 74 78 74 } //1 \cftp\Ftplist.txt
		$a_81_1 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 44 6f 77 6e 6c 6f 61 64 4d 61 6e 61 67 65 72 5c 50 61 73 73 77 6f 72 64 73 5c } //1 HKEY_CURRENT_USER\Software\DownloadManager\Passwords\
		$a_81_2 = {5c 46 54 50 47 65 74 74 65 72 5c 73 65 72 76 65 72 73 2e 78 6d 6c } //1 \FTPGetter\servers.xml
		$a_81_3 = {5c 53 6d 61 72 74 46 54 50 5c 43 6c 69 65 6e 74 20 32 2e 30 5c 46 61 76 6f 72 69 74 65 73 5c 51 75 69 63 6b 20 43 6f 6e 6e 65 63 74 5c 2a 2e 78 6d 6c } //1 \SmartFTP\Client 2.0\Favorites\Quick Connect\*.xml
		$a_81_4 = {57 73 68 53 68 65 6c 6c 2e 52 65 67 52 65 61 64 } //1 WshShell.RegRead
		$a_81_5 = {5c 46 69 6c 65 5a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //1 \FileZilla\recentservers.xml
		$a_81_6 = {5c 54 72 69 6c 6c 69 61 6e 5c 75 73 65 72 73 5c 67 6c 6f 62 61 6c 5c 61 63 63 6f 75 6e 74 73 2e 64 61 74 } //1 \Trillian\users\global\accounts.dat
		$a_81_7 = {5c 43 6c 61 77 73 2d 6d 61 69 6c } //1 \Claws-mail
		$a_81_8 = {5c 41 70 70 6c 65 20 43 6f 6d 70 75 74 65 72 5c 50 72 65 66 65 72 65 6e 63 65 73 5c 6b 65 79 63 68 61 69 6e 2e 70 6c 69 73 74 } //1 \Apple Computer\Preferences\keychain.plist
		$a_81_9 = {63 6f 6d 2e 61 70 70 6c 65 2e 53 61 66 61 72 69 } //1 com.apple.Safari
		$a_81_10 = {37 37 62 63 35 38 32 62 2d 66 30 61 36 2d 34 65 31 35 2d 34 65 38 30 2d 36 31 37 33 36 62 36 66 33 62 32 39 } //1 77bc582b-f0a6-4e15-4e80-61736b6f3b29
		$a_81_11 = {33 43 38 38 36 46 46 33 2d 32 36 36 39 2d 34 41 41 32 2d 41 38 46 42 2d 33 46 36 37 35 39 41 37 37 35 34 38 } //1 3C886FF3-2669-4AA2-A8FB-3F6759A77548
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}