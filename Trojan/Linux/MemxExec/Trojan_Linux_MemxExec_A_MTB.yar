
rule Trojan_Linux_MemxExec_A_MTB{
	meta:
		description = "Trojan:Linux/MemxExec.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 6d 65 6d 78 2f 6d 61 69 6e 2e 67 6f } //1 /memx/main.go
		$a_81_1 = {65 6e 63 6f 64 69 6e 67 2f 68 65 78 2f 68 65 78 2e 67 6f } //1 encoding/hex/hex.go
		$a_81_2 = {73 79 73 63 61 6c 6c 2f 73 79 73 63 61 6c 6c 5f 6c 69 6e 75 78 5f 61 6d 64 36 34 2e 67 6f } //1 syscall/syscall_linux_amd64.go
		$a_81_3 = {73 72 63 2f 6f 73 2f 65 78 65 63 2e 67 6f } //1 src/os/exec.go
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}