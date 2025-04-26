
rule Virus_Linux_DocCopy_L{
	meta:
		description = "Virus:Linux/DocCopy.L,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 44 61 72 6b 22 } //1 Attribute VB_Name = "Dark"
		$a_02_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 72 67 61 6e 69 7a 65 72 43 6f 70 79 20 53 6f 75 72 63 65 3a 3d [0-10] 44 65 73 74 69 6e 61 74 69 6f 6e 3a 3d [0-10] 2c 20 6e 61 6d 65 3a 3d 22 44 61 72 6b 22 2c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}