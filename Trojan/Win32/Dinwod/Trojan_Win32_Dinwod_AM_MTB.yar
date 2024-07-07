
rule Trojan_Win32_Dinwod_AM_MTB{
	meta:
		description = "Trojan:Win32/Dinwod.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {76 67 75 61 72 64 65 72 2e 39 31 69 2e 6e 65 74 2f 75 73 65 72 2e 68 74 6d } //1 vguarder.91i.net/user.htm
		$a_01_1 = {75 70 64 61 74 65 78 2e 65 78 65 } //1 updatex.exe
		$a_01_2 = {53 65 72 76 65 72 78 2e 65 78 65 } //1 Serverx.exe
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}