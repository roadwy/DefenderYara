
rule HackTool_MacOS_KeySteal_MTB{
	meta:
		description = "HackTool:MacOS/KeySteal!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {6b 65 79 73 74 65 61 6c 44 61 65 6d 6f 6e 2f 6d 61 69 6e 2e 6d 6d } //1 keystealDaemon/main.mm
		$a_00_1 = {64 65 2e 6c 69 6e 75 73 68 65 6e 7a 65 2e 6b 65 79 53 74 65 61 6c } //1 de.linushenze.keySteal
		$a_00_2 = {66 69 6c 6c 5f 6d 61 63 68 5f 70 6f 72 74 5f 61 72 72 61 79 } //1 fill_mach_port_array
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}