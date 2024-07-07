
rule HackTool_Linux_SuspSudoAttempt_A{
	meta:
		description = "HackTool:Linux/SuspSudoAttempt.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {65 00 63 00 68 00 6f 00 20 00 } //1 echo 
		$a_03_1 = {41 00 4c 00 4c 00 90 02 10 3d 00 90 00 } //1
		$a_03_2 = {41 00 4c 00 4c 00 29 00 90 02 10 41 00 4c 00 4c 00 90 00 } //1
		$a_00_3 = {2f 00 65 00 74 00 63 00 2f 00 73 00 75 00 64 00 6f 00 65 00 72 00 73 00 } //1 /etc/sudoers
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}