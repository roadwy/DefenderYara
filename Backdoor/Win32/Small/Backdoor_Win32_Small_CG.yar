
rule Backdoor_Win32_Small_CG{
	meta:
		description = "Backdoor:Win32/Small.CG,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 73 72 73 73 2e 65 78 65 00 5c 00 6e 6f 74 69 66 69 79 00 76 69 63 74 75 6d 00 c7 e1 d6 cd ed c9 78 00 } //1
		$a_01_1 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 00 2e 64 6c 6c 00 67 65 6e 72 61 6c 00 64 6c 6c 69 6e 6b 65 72 00 45 78 70 6c 6f 72 65 72 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}