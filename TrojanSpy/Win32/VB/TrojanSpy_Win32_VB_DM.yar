
rule TrojanSpy_Win32_VB_DM{
	meta:
		description = "TrojanSpy:Win32/VB.DM,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 00 63 00 2d 00 73 00 63 00 72 00 69 00 70 00 74 00 73 00 2e 00 6e 00 6f 00 2d 00 69 00 70 00 2e 00 6f 00 72 00 67 00 } //3 pc-scripts.no-ip.org
		$a_01_1 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 46 00 49 00 4c 00 45 00 53 00 2e 00 65 00 78 00 65 00 } //2 C:\WINDOWS\WINDOWSFILES.exe
		$a_01_2 = {48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 79 00 61 00 68 00 6f 00 6f 00 5c 00 70 00 61 00 67 00 65 00 72 00 5c 00 45 00 54 00 53 00 } //2 HKCU\Software\yahoo\pager\ETS
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}