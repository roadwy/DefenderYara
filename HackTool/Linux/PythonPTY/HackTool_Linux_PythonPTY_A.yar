
rule HackTool_Linux_PythonPTY_A{
	meta:
		description = "HackTool:Linux/PythonPTY.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 09 00 00 05 00 "
		
	strings :
		$a_00_0 = {69 00 6d 00 70 00 6f 00 72 00 74 00 20 00 70 00 74 00 79 00 } //05 00  import pty
		$a_00_1 = {70 00 74 00 79 00 2e 00 73 00 70 00 61 00 77 00 6e 00 28 00 } //01 00  pty.spawn(
		$a_00_2 = {2f 00 62 00 69 00 6e 00 2f 00 62 00 61 00 73 00 68 00 } //01 00  /bin/bash
		$a_00_3 = {2f 00 62 00 69 00 6e 00 2f 00 64 00 61 00 73 00 68 00 } //01 00  /bin/dash
		$a_00_4 = {2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 } //01 00  /bin/sh
		$a_00_5 = {2f 00 62 00 69 00 6e 00 2f 00 7a 00 73 00 68 00 } //01 00  /bin/zsh
		$a_00_6 = {2f 00 62 00 69 00 6e 00 2f 00 6b 00 73 00 68 00 39 00 33 00 } //01 00  /bin/ksh93
		$a_00_7 = {2f 00 62 00 69 00 6e 00 2f 00 6b 00 73 00 68 00 } //01 00  /bin/ksh
		$a_00_8 = {2f 00 62 00 69 00 6e 00 2f 00 74 00 63 00 73 00 68 00 } //00 00  /bin/tcsh
	condition:
		any of ($a_*)
 
}