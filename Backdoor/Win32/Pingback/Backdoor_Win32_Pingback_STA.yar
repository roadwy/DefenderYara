
rule Backdoor_Win32_Pingback_STA{
	meta:
		description = "Backdoor:Win32/Pingback.STA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 54 43 50 42 44 53 56 32 2e 70 64 62 } //1 \TCPBDSV2.pdb
		$a_00_1 = {6f 70 65 6e 66 69 6c 65 20 6f 6e 20 72 65 6d 6f 74 65 20 63 6f 6d 70 75 74 65 72 73 20 73 75 63 63 65 73 73 } //1 openfile on remote computers success
		$a_02_2 = {73 68 65 6c 6c [0-0a] 64 69 72 20 } //1
		$a_02_3 = {4e 45 4e 44 [0-0a] 65 78 65 70 00 } //1
		$a_02_4 = {43 72 65 61 74 65 46 69 6c 65 [0-0a] 50 65 65 6b 4e 61 6d 65 64 50 69 70 [0-0a] 57 72 69 74 65 46 69 6c 65 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}