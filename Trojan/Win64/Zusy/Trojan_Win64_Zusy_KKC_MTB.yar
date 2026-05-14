
rule Trojan_Win64_Zusy_KKC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 6f 72 5f 64 61 74 61 2e 64 61 74 } //10 xor_data.dat
		$a_01_1 = {63 75 73 74 6f 6d 5f 73 74 72 65 61 6d 5f 64 61 74 61 2e 64 61 74 } //10 custom_stream_data.dat
		$a_01_2 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 6d 75 6c 74 69 5f 63 75 73 74 6f 6d 5f 73 74 72 65 61 6d } //4 bypass\bypass-agent\workspace\ssvagent_multi_custom_stream
		$a_01_3 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5f 32 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 74 68 72 65 61 64 6c 65 73 73 5f 78 6f 72 5f } //4 bypass\bypass-agent_2\workspace\ssvagent_threadless_xor_
		$a_01_4 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 72 65 6d 6f 74 65 5f 74 68 72 65 61 64 5f 68 69 6a 61 63 6b 5f 78 6f 72 5f } //4 bypass\bypass-agent\workspace\ssvagent_remote_thread_hijack_xor_
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4) >=14
 
}