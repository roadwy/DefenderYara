
rule Backdoor_Win32_Zegost_H_dll{
	meta:
		description = "Backdoor:Win32/Zegost.H!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {4c 24 5f 52 61 73 44 65 66 61 75 6c 74 43 72 65 64 65 6e 74 69 61 6c 73 23 30 00 00 52 61 73 44 69 61 6c 50 61 72 61 6d 73 21 25 73 23 30 00 00 44 65 76 69 63 65 00 00 50 68 6f 6e 65 4e 75 6d 62 65 72 } //2
		$a_01_1 = {70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 4e 65 74 77 6f 72 6b 5c 43 6f 6e 6e 65 63 74 69 6f 6e 73 5c 70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //2 plication Data\Microsoft\Network\Connections\pbk\rasphone.pbk
		$a_01_2 = {5c 73 79 73 6c 6f 67 2e 64 61 74 } //1 \syslog.dat
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 Applications\iexplore.exe\shell\open\command
		$a_01_4 = {47 6c 6f 62 61 6c 5c 64 66 67 25 64 38 64 34 67 } //1 Global\dfg%d8d4g
		$a_03_5 = {b9 10 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab c7 85 ?? ?? ff ff 44 00 00 00 c6 45 ?? 57 c6 45 ?? 69 c6 45 ?? 6e c6 45 ?? 53 c6 45 ?? 74 } //2
		$a_01_6 = {45 6e 61 62 6c 65 41 64 6d 69 6e 54 53 52 65 6d 6f 74 65 } //1 EnableAdminTSRemote
		$a_01_7 = {53 68 75 74 64 6f 77 6e 57 69 74 68 6f 75 74 4c 6f 67 6f 6e } //1 ShutdownWithoutLogon
		$a_01_8 = {66 44 65 6e 79 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //1 fDenyTSConnections
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}