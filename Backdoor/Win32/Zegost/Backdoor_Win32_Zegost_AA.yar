
rule Backdoor_Win32_Zegost_AA{
	meta:
		description = "Backdoor:Win32/Zegost.AA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00 7a 77 67 78 } //1
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 Applications\iexplore.exe\shell\open\command
		$a_01_2 = {5f 6b 61 73 70 65 72 73 6b 79 } //1 _kaspersky
		$a_01_3 = {44 72 61 67 6f 6e 4e 65 73 74 2e 65 78 65 } //1 DragonNest.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}