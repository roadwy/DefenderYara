
rule Trojan_Win32_RustzExec_A_MTB{
	meta:
		description = "Trojan:Win32/RustzExec.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 72 63 5c 63 6c 69 65 6e 74 5c 63 6c 69 65 6e 74 2e 72 73 } //1 src\client\client.rs
		$a_81_1 = {73 72 63 5c 70 72 6f 78 79 2e 72 73 } //1 src\proxy.rs
		$a_81_2 = {73 72 63 5c 74 61 73 6b 5c 64 6f 77 6e 6c 6f 61 64 2e 72 73 } //1 src\task\download.rs
		$a_81_3 = {73 70 61 77 6e 69 6e 67 } //1 spawning
		$a_81_4 = {73 72 63 5c 74 61 73 6b 5c 65 78 65 63 75 74 65 2e 72 73 } //1 src\task\execute.rs
		$a_02_5 = {68 74 74 70 [0-10] 2e 63 72 65 70 2e } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}