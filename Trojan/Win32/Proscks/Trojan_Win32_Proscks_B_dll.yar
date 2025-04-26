
rule Trojan_Win32_Proscks_B_dll{
	meta:
		description = "Trojan:Win32/Proscks.B!dll,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 57 69 6e 44 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 44 6c 6c 63 61 63 68 65 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 %WinDir%\System32\Dllcache\svchost.exe
		$a_01_1 = {70 72 6f 78 79 2e 64 6c 6c 00 72 61 6e 64 } //1
		$a_01_2 = {6e 65 74 20 73 74 6f 70 20 22 73 68 61 72 65 64 61 63 63 65 73 73 22 } //1 net stop "sharedaccess"
		$a_01_3 = {6d 61 63 3d 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 3a 25 30 32 58 } //1 mac=%02X:%02X:%02X:%02X:%02X:%02X
		$a_01_4 = {70 72 6f 78 79 20 70 77 64 3d 25 73 } //1 proxy pwd=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}