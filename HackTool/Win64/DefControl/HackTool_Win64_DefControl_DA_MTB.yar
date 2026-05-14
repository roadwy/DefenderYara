
rule HackTool_Win64_DefControl_DA_MTB{
	meta:
		description = "HackTool:Win64/DefControl.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_81_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6c 6b 61 72 6c 73 6c 75 6e 64 2f 64 65 66 65 6e 64 65 72 2d 61 63 6c 2d 62 6c 6f 63 6b 65 72 } //10 github.com/lkarlslund/defender-acl-blocker
		$a_81_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_81_2 = {63 72 79 70 74 6f 2f 69 6e 74 65 72 6e 61 6c 2f 66 69 70 73 31 34 30 2f 61 65 73 2e 65 6e 63 72 79 70 74 42 6c 6f 63 6b } //1 crypto/internal/fips140/aes.encryptBlock
		$a_81_3 = {63 72 79 70 74 6f 2f 69 6e 74 65 72 6e 61 6c 2f 66 69 70 73 31 34 30 2f 61 65 73 2e 64 65 63 72 79 70 74 42 6c 6f 63 6b } //1 crypto/internal/fips140/aes.decryptBlock
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}