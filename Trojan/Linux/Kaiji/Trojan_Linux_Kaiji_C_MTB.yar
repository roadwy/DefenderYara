
rule Trojan_Linux_Kaiji_C_MTB{
	meta:
		description = "Trojan:Linux/Kaiji.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,20 00 20 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 43 56 45 } //10 main.CVE
		$a_00_1 = {2e 72 6e 67 } //10 .rng
		$a_00_2 = {66 6f 72 63 65 61 74 74 65 6d 70 74 68 74 74 70 } //10 forceattempthttp
		$a_00_3 = {73 79 73 63 61 6c 6c 2e 61 63 63 65 70 74 } //1 syscall.accept
		$a_00_4 = {73 79 73 63 61 6c 6c 2e 63 6f 6e 6e 65 63 74 } //1 syscall.connect
		$a_00_5 = {73 79 73 63 61 6c 6c 2e 73 65 6e 64 66 69 6c 65 } //1 syscall.sendfile
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=32
 
}