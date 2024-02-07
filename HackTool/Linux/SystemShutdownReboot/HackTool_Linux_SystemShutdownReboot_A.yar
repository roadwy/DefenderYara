
rule HackTool_Linux_SystemShutdownReboot_A{
	meta:
		description = "HackTool:Linux/SystemShutdownReboot.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 00 61 00 6c 00 74 00 } //01 00  halt
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 6f 00 66 00 66 00 } //01 00  poweroff
		$a_00_2 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 } //01 00  shutdown
		$a_00_3 = {72 00 65 00 62 00 6f 00 6f 00 74 00 } //00 00  reboot
	condition:
		any of ($a_*)
 
}