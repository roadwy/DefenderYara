
rule TrojanDropper_Win32_VB_IP{
	meta:
		description = "TrojanDropper:Win32/VB.IP,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 00 6d 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 amhost.exe
		$a_01_1 = {62 00 6d 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 bmhost.exe
		$a_01_2 = {63 00 6d 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 cmhost.exe
		$a_01_3 = {64 00 6d 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 dmhost.exe
		$a_01_4 = {65 00 6d 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 emhost.exe
		$a_01_5 = {66 00 6d 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 fmhost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}