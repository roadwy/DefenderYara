
rule HackTool_Linux_DisableTTY_A{
	meta:
		description = "HackTool:Linux/DisableTTY.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 00 63 00 68 00 6f 00 20 00 } //01 00  echo 
		$a_01_1 = {44 00 65 00 66 00 61 00 75 00 6c 00 74 00 73 00 20 00 21 00 74 00 74 00 79 00 5f 00 74 00 69 00 63 00 6b 00 65 00 74 00 73 00 } //01 00  Defaults !tty_tickets
		$a_00_2 = {2f 00 65 00 74 00 63 00 2f 00 73 00 75 00 64 00 6f 00 65 00 72 00 73 00 } //00 00  /etc/sudoers
	condition:
		any of ($a_*)
 
}