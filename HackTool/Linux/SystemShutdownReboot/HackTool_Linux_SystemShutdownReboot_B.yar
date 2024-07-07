
rule HackTool_Linux_SystemShutdownReboot_B{
	meta:
		description = "HackTool:Linux/SystemShutdownReboot.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 00 6e 00 69 00 74 00 20 00 30 00 } //1 init 0
		$a_00_1 = {69 00 6e 00 69 00 74 00 20 00 36 00 } //1 init 6
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}