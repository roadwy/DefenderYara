
rule Trojan_Win32_GoAgent_B_MTB{
	meta:
		description = "Trojan:Win32/GoAgent.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 25 73 } //1 User-Agent: %s
		$a_81_1 = {63 72 79 70 74 6f 2f 73 75 62 74 6c 65 2f 78 6f 72 2e 67 6f } //1 crypto/subtle/xor.go
		$a_81_2 = {73 79 73 63 61 6c 6c 2f 73 79 73 63 61 6c 6c 2e 67 6f } //1 syscall/syscall.go
		$a_81_3 = {65 6e 63 6f 64 69 6e 67 2f 62 61 73 65 36 34 2f 62 61 73 65 36 34 2e 67 6f } //1 encoding/base64/base64.go
		$a_81_4 = {2e 48 6f 6c 6c 6f 77 50 72 6f 63 65 73 73 } //1 .HollowProcess
		$a_81_5 = {2e 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 .WriteProcessMemory
		$a_81_6 = {2e 47 65 74 52 65 6d 6f 74 65 50 65 62 41 64 64 72 } //1 .GetRemotePebAddr
		$a_81_7 = {2e 52 65 64 69 72 65 63 74 54 6f 50 61 79 6c 6f 61 64 } //1 .RedirectToPayload
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}