
rule Backdoor_Win32_Zegost_BK{
	meta:
		description = "Backdoor:Win32/Zegost.BK,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
		$a_01_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 57 69 6e 53 74 61 74 69 6f 6e 73 5c 52 44 50 2d 54 63 70 } //4 SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //2 Applications\iexplore.exe\shell\open\command
		$a_01_3 = {5c 6b 65 79 6c 6f 67 2e 64 61 74 } //2 \keylog.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=9
 
}