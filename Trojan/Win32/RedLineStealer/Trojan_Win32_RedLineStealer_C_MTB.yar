
rule Trojan_Win32_RedLineStealer_C_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 63 6d 64 20 3c 20 41 67 69 6e 67 2e 61 64 74 20 26 20 70 69 6e 67 20 2d 6e 20 35 20 6c 6f 63 61 6c 68 6f 73 74 } //2 cmd /c cmd < Aging.adt & ping -n 5 localhost
		$a_01_1 = {6e 73 6c 6f 6f 6b 75 70 20 2f } //1 nslookup /
		$a_01_2 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 } //2 Software\Microsoft\Windows\CurrentVersion\App Paths
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}