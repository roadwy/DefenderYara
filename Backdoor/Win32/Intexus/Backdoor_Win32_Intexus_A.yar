
rule Backdoor_Win32_Intexus_A{
	meta:
		description = "Backdoor:Win32/Intexus.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {25 57 69 6e 44 69 72 25 5c 68 6f 73 74 73 } //1 %WinDir%\hosts
		$a_00_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 54 63 70 69 70 5c 50 61 72 61 6d 65 74 65 72 73 } //1 SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
		$a_00_2 = {68 6f 73 74 6c 69 73 74 } //1 hostlist
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 52 41 53 20 41 75 74 6f 44 69 61 6c 5c 43 6f 6e 74 72 6f 6c } //1 Software\Microsoft\RAS AutoDial\Control
		$a_00_4 = {45 6e 61 62 6c 65 41 75 74 6f 64 69 61 6c } //1 EnableAutodial
		$a_00_5 = {4e 6f 4e 65 77 41 75 74 6f 64 69 61 6c } //1 NoNewAutodial
		$a_00_6 = {43 6f 6f 70 49 6e 74 65 78 44 69 61 6c } //1 CoopIntexDial
		$a_01_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_8 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_9 = {49 00 6e 00 74 00 65 00 78 00 44 00 69 00 61 00 6c 00 } //1 IntexDial
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}