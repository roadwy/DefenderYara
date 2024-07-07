
rule Backdoor_Win32_Canoswei_A{
	meta:
		description = "Backdoor:Win32/Canoswei.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 41 75 74 6f 72 75 6e 2e 76 62 73 } //1 \Autorun.vbs
		$a_01_1 = {5b 73 79 6e 5d } //1 [syn]
		$a_01_2 = {5b 66 6c 6f 6f 64 73 74 6f 70 5d } //1 [floodstop]
		$a_01_3 = {5b 68 61 6c 74 5d } //1 [halt]
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 5f 55 70 64 61 74 65 73 5f } //1 Microsoft_Updates_
		$a_01_5 = {2e 70 68 70 3f } //1 .php?
		$a_01_6 = {77 77 77 2e 77 65 69 73 73 2d 63 61 6e 6e 6f 6e 2e 64 65 } //1 www.weiss-cannon.de
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}