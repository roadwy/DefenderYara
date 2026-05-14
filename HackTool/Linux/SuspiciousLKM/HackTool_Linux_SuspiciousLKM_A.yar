
rule HackTool_Linux_SuspiciousLKM_A{
	meta:
		description = "HackTool:Linux/SuspiciousLKM.A,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_80_0 = {4d 61 6e 64 69 61 6e 74 20 4b 65 72 6e 65 6c 20 4d 6f 64 75 6c 65 20 6c 6f 61 64 65 64 } //Mandiant Kernel Module loaded  6
	condition:
		((#a_80_0  & 1)*6) >=6
 
}