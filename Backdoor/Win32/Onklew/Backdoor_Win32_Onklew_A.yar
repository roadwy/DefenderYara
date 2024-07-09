
rule Backdoor_Win32_Onklew_A{
	meta:
		description = "Backdoor:Win32/Onklew.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 6c 79 4f 6e 65 4b 65 77 } //1 OnlyOneKew
		$a_01_1 = {52 75 6e 55 72 6c 4b 65 77 } //1 RunUrlKew
		$a_01_2 = {64 6e 73 63 6b 2e 68 6f 75 73 66 2e 6e 65 74 } //1 dnsck.housf.net
		$a_03_3 = {47 53 4e 61 6d 65 3d [0-0c] 53 79 73 3d [0-0c] 50 63 4e 61 6d 65 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}