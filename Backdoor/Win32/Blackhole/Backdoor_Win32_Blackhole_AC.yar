
rule Backdoor_Win32_Blackhole_AC{
	meta:
		description = "Backdoor:Win32/Blackhole.AC,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 2e 74 6d 70 00 53 75 70 65 72 2d 45 43 00 } //1
		$a_01_1 = {00 5c 63 2e 73 79 73 00 } //1
		$a_01_2 = {77 67 68 61 69 2e 63 6f 6d } //1 wghai.com
		$a_01_3 = {5c 41 76 65 6e 67 65 72 2d 44 65 73 74 72 75 63 74 69 6f 6e 2e 64 6c 6c 00 } //1
		$a_01_4 = {6d 67 6d 74 73 3a 7b 69 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 3d 69 6d 70 65 72 73 6f 6e 61 74 65 7d 22 29 2e 49 6e 73 74 61 6e 63 65 73 4f 66 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 22 29 } //1 mgmts:{impersonationLevel=impersonate}").InstancesOf("Win32_Processor")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}