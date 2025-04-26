
rule Trojan_Win32_AgentTesla_G_{
	meta:
		description = "Trojan:Win32/AgentTesla.G!!AgentTesla.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {5c 4d 6f 7a 69 6c 6c 61 5c 69 63 65 63 61 74 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 \Mozilla\icecat\profiles.ini
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 44 6f 77 6e 6c 6f 61 64 4d 61 6e 61 67 65 72 5c 50 61 73 73 77 6f 72 64 73 5c } //1 Software\DownloadManager\Passwords\
		$a_81_2 = {5c 46 54 50 47 65 74 74 65 72 5c 73 65 72 76 65 72 73 2e 78 6d 6c 20 5c 46 6c 61 73 68 46 58 50 5c 33 71 75 69 63 6b 2e 64 61 74 } //1 \FTPGetter\servers.xml \FlashFXP\3quick.dat
		$a_81_3 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 51 75 61 6c 63 6f 6d 6d 5c 45 75 64 6f 72 61 5c 43 6f 6d 6d 61 6e 64 4c 69 6e 65 } //1 HKEY_CURRENT_USER\Software\Qualcomm\Eudora\CommandLine
		$a_81_4 = {5c 50 6f 73 74 62 6f 78 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 \Postbox\profiles.ini
		$a_81_5 = {5c 4e 45 54 47 41 54 45 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 5c 42 6c 61 63 6b 48 61 77 6b 5c } //1 \NETGATE Technologies\BlackHawk\
		$a_81_6 = {5c 4d 6f 6f 6e 63 68 69 6c 64 20 50 72 6f 64 75 63 74 69 6f 6e 73 5c 50 61 6c 65 20 4d 6f 6f 6e 5c 20 } //1 \Moonchild Productions\Pale Moon\ 
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}