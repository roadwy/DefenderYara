
rule Backdoor_Win32_Tripshell_A{
	meta:
		description = "Backdoor:Win32/Tripshell.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 68 6f 70 70 69 6e 67 2e 6b 64 64 69 2d 63 6c 6f 75 64 2e 63 6f 6d } //2 shopping.kddi-cloud.com
		$a_01_1 = {2f 00 6e 00 65 00 77 00 73 00 3f 00 25 00 63 00 3d 00 25 00 58 00 25 00 58 00 } //1 /news?%c=%X%X
		$a_01_2 = {2f 00 4e 00 25 00 75 00 2e 00 6a 00 73 00 70 00 3f 00 6d 00 3d 00 25 00 64 00 } //1 /N%u.jsp?m=%d
		$a_01_3 = {46 72 6f 6e 74 53 68 65 6c 6c 5f 5b 4d 61 72 6b 5d 2e 64 6c 6c } //2 FrontShell_[Mark].dll
		$a_01_4 = {00 50 72 69 6e 74 46 00 } //1 倀楲瑮F
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=7
 
}