
rule HackTool_Linux_Ncrack_C{
	meta:
		description = "HackTool:Linux/Ncrack.C,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {6e 63 72 61 63 6b 2d 73 65 72 76 69 63 65 73 } //2 ncrack-services
		$a_00_1 = {4e 63 72 61 63 6b 20 64 6f 6e 65 3a } //2 Ncrack done:
		$a_01_2 = {4e 63 72 61 63 6b 20 69 73 20 75 73 69 6e 67 20 25 73 20 66 6f 72 20 73 65 63 75 72 69 74 79 } //2 Ncrack is using %s for security
		$a_00_3 = {6e 63 72 61 63 6b 5f 70 72 6f 62 65 73 } //2 ncrack_probes
		$a_00_4 = {66 79 6f 64 6f 72 40 69 6e 73 65 63 75 72 65 2e 6f 72 67 20 73 6f 20 69 20 63 61 6e 20 67 75 61 67 65 20 73 75 70 70 6f 72 74 } //2 fyodor@insecure.org so i can guage support
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}