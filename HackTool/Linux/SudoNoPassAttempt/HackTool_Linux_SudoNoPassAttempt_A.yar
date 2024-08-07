
rule HackTool_Linux_SudoNoPassAttempt_A{
	meta:
		description = "HackTool:Linux/SudoNoPassAttempt.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {65 00 63 00 68 00 6f 00 20 00 } //1 echo 
		$a_03_1 = {41 00 4c 00 4c 00 [0-10] 3d 00 } //1
		$a_03_2 = {4e 00 4f 00 50 00 41 00 53 00 53 00 57 00 44 00 3a 00 [0-10] 41 00 4c 00 4c 00 } //1
		$a_00_3 = {2f 00 65 00 74 00 63 00 2f 00 73 00 75 00 64 00 6f 00 65 00 72 00 73 00 } //1 /etc/sudoers
		$a_00_4 = {61 00 7a 00 75 00 72 00 65 00 5f 00 70 00 69 00 70 00 65 00 6c 00 69 00 6e 00 65 00 73 00 5f 00 73 00 75 00 64 00 6f 00 } //-10 azure_pipelines_sudo
		$a_00_5 = {77 00 69 00 6e 00 62 00 69 00 6e 00 64 00 } //-10 winbind
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*-10+(#a_00_5  & 1)*-10) >=4
 
}