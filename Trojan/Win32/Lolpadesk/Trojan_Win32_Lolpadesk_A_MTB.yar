
rule Trojan_Win32_Lolpadesk_A_MTB{
	meta:
		description = "Trojan:Win32/Lolpadesk.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {4c 4f 4c 50 41 34 44 45 53 4b } //2 LOLPA4DESK
		$a_01_2 = {45 6e 75 6d 44 65 73 6b 74 6f 70 57 69 6e 64 6f 77 73 } //1 EnumDesktopWindows
		$a_01_3 = {67 65 74 61 64 64 72 69 6e 66 6f } //1 getaddrinfo
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}