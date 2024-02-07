
rule Trojan_Win32_BHO_EF{
	meta:
		description = "Trojan:Win32/BHO.EF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 04 00 "
		
	strings :
		$a_00_0 = {65 3a 5c 4a 69 6e 5a 51 5c } //04 00  e:\JinZQ\
		$a_00_1 = {73 74 61 74 2e 77 61 6d 6d 65 2e 63 6e } //02 00  stat.wamme.cn
		$a_01_2 = {47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 } //02 00  GameVersionUpdate
		$a_00_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 31 2e 69 6e 69 } //01 00  C:\WINDOWS\system32\drivers\etc\service1.ini
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b } //01 00  Software\Microsoft\Windows\CurrentVersion\Policies\Network
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //01 00  Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
		$a_01_6 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //01 00  NoNetConnectDisconnect
		$a_00_7 = {25 32 5c 70 72 6f 74 6f 63 6f 6c 5c 53 74 64 46 69 6c 65 45 64 69 74 69 6e 67 5c 73 65 72 76 65 72 } //00 00  %2\protocol\StdFileEditing\server
	condition:
		any of ($a_*)
 
}