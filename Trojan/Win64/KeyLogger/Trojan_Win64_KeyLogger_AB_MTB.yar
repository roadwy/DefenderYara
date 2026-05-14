
rule Trojan_Win64_KeyLogger_AB_MTB{
	meta:
		description = "Trojan:Win64/KeyLogger.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6b 65 6e 7a 5f 6d 75 74 65 78 } //1 kenz_mutex
		$a_81_1 = {43 32 20 74 68 72 65 61 64 20 73 74 61 72 74 65 64 2e } //1 C2 thread started.
		$a_81_2 = {4b 65 79 6c 6f 67 67 65 72 20 73 74 61 72 74 65 64 2e } //1 Keylogger started.
		$a_81_3 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 72 75 6c 65 20 67 72 6f 75 70 3d 22 72 65 6d 6f 74 65 20 64 65 73 6b 74 6f 70 22 20 6e 65 77 20 65 6e 61 62 6c 65 3d 59 65 73 20 3e 20 6e 75 6c } //1 netsh advfirewall firewall set rule group="remote desktop" new enable=Yes > nul
		$a_81_4 = {43 68 65 63 6b 20 66 61 69 6c 65 64 3a 20 56 4d 77 61 72 65 20 54 6f 6f 6c 73 20 72 65 67 69 73 74 72 79 20 6b 65 79 20 66 6f 75 6e 64 2e } //1 Check failed: VMware Tools registry key found.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}