
rule Backdoor_Win32_Zupdax_B_dha{
	meta:
		description = "Backdoor:Win32/Zupdax.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 75 00 70 00 64 00 61 00 74 00 61 00 5c 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 00 00 } //1
		$a_01_1 = {72 65 61 64 5f 64 6c 6c 5f 6d 65 6d 6f 72 79 5f 6c 6f 61 64 5f 73 68 65 6c 6c 63 6f 64 65 } //1 read_dll_memory_load_shellcode
		$a_01_2 = {43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 66 69 6c 65 20 64 6c 6c 2e 62 69 6e } //1 Could not open file dll.bin
		$a_01_3 = {72 00 75 00 6e 00 5f 00 74 00 72 00 61 00 6e 00 73 00 70 00 6f 00 72 00 74 00 } //1 run_transport
		$a_01_4 = {50 6c 75 67 69 6e 52 65 63 76 45 78 65 63 75 74 65 50 72 6f 63 } //1 PluginRecvExecuteProc
		$a_01_5 = {73 65 72 76 65 72 20 6d 79 74 68 72 65 61 64 } //1 server mythread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}