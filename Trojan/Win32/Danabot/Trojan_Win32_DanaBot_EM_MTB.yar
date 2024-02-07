
rule Trojan_Win32_DanaBot_EM_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 76 64 2d 6b 2d 74 75 6c 61 2e 72 75 } //01 00  mvd-k-tula.ru
		$a_01_1 = {4b 45 59 4b 45 59 30 35 } //01 00  KEYKEY05
		$a_01_2 = {43 3a 5c 47 61 6c 61 78 36 4b 5c 64 6f 62 61 6c 6f 63 2e 65 78 65 } //01 00  C:\Galax6K\dobaloc.exe
		$a_01_3 = {4d 65 73 73 61 67 65 42 65 65 70 } //01 00  MessageBeep
		$a_01_4 = {47 65 74 55 73 65 72 4e 61 6d 65 41 } //01 00  GetUserNameA
		$a_01_5 = {57 53 41 53 74 61 72 74 75 70 } //00 00  WSAStartup
	condition:
		any of ($a_*)
 
}