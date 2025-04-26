
rule Trojan_Win32_TunelzRustz_A_MTB{
	meta:
		description = "Trojan:Win32/TunelzRustz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {73 72 63 2f 6e 65 74 2f 74 63 70 2f 73 6f 63 6b 65 74 2e 72 73 } //1 src/net/tcp/socket.rs
		$a_81_1 = {73 72 63 2f 70 72 6f 78 79 2e 72 73 } //1 src/proxy.rs
		$a_81_2 = {50 69 6e 67 61 63 6b 70 61 79 6c 6f 61 64 } //1 Pingackpayload
		$a_81_3 = {65 6e 63 6f 64 65 64 20 73 65 74 74 69 6e 67 73 } //1 encoded settings
		$a_81_4 = {65 6e 63 6f 64 65 64 20 70 69 6e 67 } //1 encoded ping
		$a_81_5 = {65 6e 63 6f 64 65 64 20 67 6f 5f 61 77 61 79 } //1 encoded go_away
		$a_81_6 = {65 6e 63 6f 64 65 64 20 77 69 6e 64 6f 77 5f 75 70 64 61 74 65 } //1 encoded window_update
		$a_81_7 = {65 6e 63 6f 64 65 64 20 72 65 73 65 74 } //1 encoded reset
		$a_81_8 = {73 72 63 2f 72 75 6e 74 69 6d 65 2f 74 61 73 6b 2f 63 6f 72 65 2e 72 73 } //1 src/runtime/task/core.rs
		$a_81_9 = {4c 6f 61 64 65 64 20 20 70 72 6f 78 69 65 73 } //1 Loaded  proxies
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}