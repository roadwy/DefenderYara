
rule HackTool_Linux_DiscoverCredentials_BZ4{
	meta:
		description = "HackTool:Linux/DiscoverCredentials.BZ4,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {67 00 72 00 65 00 70 00 20 00 } //10 grep 
		$a_00_1 = {70 00 65 00 6d 00 7c 00 6b 00 65 00 79 00 7c 00 63 00 72 00 65 00 64 00 7c 00 64 00 62 00 7c 00 73 00 71 00 6c 00 69 00 74 00 65 00 7c 00 63 00 6f 00 6e 00 66 00 7c 00 63 00 6e 00 66 00 7c 00 69 00 6e 00 69 00 7c 00 65 00 6e 00 76 00 7c 00 73 00 65 00 63 00 72 00 65 00 74 00 7c 00 74 00 6f 00 6b 00 65 00 6e 00 7c 00 61 00 75 00 74 00 68 00 7c 00 70 00 61 00 73 00 73 00 77 00 64 00 7c 00 73 00 68 00 61 00 64 00 6f 00 77 00 } //10 pem|key|cred|db|sqlite|conf|cnf|ini|env|secret|token|auth|passwd|shadow
		$a_02_2 = {2f 00 70 00 72 00 6f 00 63 00 2f 00 [0-40] 2f 00 6d 00 61 00 70 00 73 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10) >=30
 
}