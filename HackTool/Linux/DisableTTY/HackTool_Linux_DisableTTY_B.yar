
rule HackTool_Linux_DisableTTY_B{
	meta:
		description = "HackTool:Linux/DisableTTY.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 64 00 20 00 } //1 sed 
		$a_00_1 = {73 00 2f 00 65 00 6e 00 76 00 5f 00 72 00 65 00 73 00 65 00 74 00 2e 00 2a 00 24 00 2f 00 65 00 6e 00 76 00 5f 00 72 00 65 00 73 00 65 00 74 00 2c 00 74 00 69 00 6d 00 65 00 73 00 74 00 61 00 6d 00 70 00 5f 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 3d 00 2d 00 31 00 2f 00 } //1 s/env_reset.*$/env_reset,timestamp_timeout=-1/
		$a_00_2 = {2f 00 65 00 74 00 63 00 2f 00 73 00 75 00 64 00 6f 00 65 00 72 00 73 00 } //1 /etc/sudoers
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}