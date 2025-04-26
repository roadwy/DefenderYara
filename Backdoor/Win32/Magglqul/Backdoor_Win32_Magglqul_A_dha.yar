
rule Backdoor_Win32_Magglqul_A_dha{
	meta:
		description = "Backdoor:Win32/Magglqul.A!dha,SIGNATURE_TYPE_PEHSTR,06 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 46 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 55 00 73 00 65 00 72 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 57 00 68 00 65 00 72 00 65 00 20 00 4c 00 6f 00 63 00 61 00 6c 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 3d 00 20 00 54 00 72 00 75 00 65 00 } //1 Select *From Win32_UserAccount Where LocalAccount = True
		$a_01_1 = {49 74 27 73 20 42 6c 6f 63 6b 69 6e 67 20 49 2f 4f } //1 It's Blocking I/O
		$a_01_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 57 69 6e 53 74 61 74 69 6f 6e 73 5c 52 44 50 2d 54 63 70 } //1 SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
		$a_01_3 = {45 6c 65 76 61 74 65 54 53 20 55 73 65 72 20 50 61 73 73 77 6f 72 64 20 50 6f 72 74 } //1 ElevateTS User Password Port
		$a_01_4 = {54 68 65 20 41 63 63 6f 75 6e 74 20 25 73 20 48 61 73 20 42 65 65 6e 20 43 6c 6f 6e 65 64 20 54 6f 20 25 73 } //1 The Account %s Has Been Cloned To %s
		$a_01_5 = {65 78 65 63 20 6d 61 73 74 65 72 2e 64 62 6f 2e 73 70 5f 61 64 64 6c 6f 67 69 6e 20 25 73 2c 25 73 3b 65 78 65 63 20 6d 61 73 74 65 72 2e 64 62 6f 2e 73 70 5f 61 64 64 73 72 76 72 6f 6c 65 6d 65 6d 62 65 72 20 25 73 2c 73 79 73 61 64 6d 69 6e } //1 exec master.dbo.sp_addlogin %s,%s;exec master.dbo.sp_addsrvrolemember %s,sysadmin
		$a_01_6 = {48 6f 73 74 4c 69 73 74 20 5b 50 6f 72 74 5d 20 55 73 65 72 4c 69 73 74 20 50 61 73 73 4c 69 73 74 20 54 68 72 65 61 64 } //1 HostList [Port] UserList PassList Thread
		$a_01_7 = {53 71 6c 53 63 61 6e } //1 SqlScan
		$a_01_8 = {52 53 68 65 6c 6c } //1 RShell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}