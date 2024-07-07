
rule Backdoor_Win32_Hikiti_N_dha{
	meta:
		description = "Backdoor:Win32/Hikiti.N!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 65 76 69 6c 2d 63 6f 64 65 73 5c 62 69 6e 5c 78 56 69 72 75 73 2e 70 64 62 00 } //1
		$a_01_1 = {c1 e8 02 40 8b d0 c1 e2 02 2b ca 8b f9 31 1e 83 c6 04 48 75 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Backdoor_Win32_Hikiti_N_dha_2{
	meta:
		description = "Backdoor:Win32/Hikiti.N!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 1e 83 c6 04 48 75 f8 } //1
		$a_01_1 = {68 69 6b 69 74 } //1 hikit
		$a_01_2 = {4f 00 70 00 65 00 6e 00 20 00 62 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00 20 00 65 00 72 00 72 00 6f 00 72 00 2e 00 } //1 Open backdoor error.
		$a_01_3 = {43 00 72 00 65 00 61 00 74 00 65 00 50 00 69 00 70 00 65 00 20 00 68 00 52 00 65 00 61 00 64 00 50 00 69 00 70 00 65 00 53 00 68 00 65 00 6c 00 6c 00 20 00 26 00 20 00 68 00 57 00 72 00 69 00 74 00 65 00 50 00 69 00 70 00 65 00 48 00 61 00 6e 00 64 00 6c 00 65 00 20 00 65 00 72 00 72 00 6f 00 72 00 20 00 3d 00 20 00 25 00 73 00 } //1 CreatePipe hReadPipeShell & hWritePipeHandle error = %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}