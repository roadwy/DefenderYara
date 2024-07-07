
rule Virus_Linux_Thus_GC{
	meta:
		description = "Virus:Linux/Thus.GC,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 69 74 68 20 48 6f 73 74 0d 0a 20 20 20 20 49 66 20 2e 4c 69 6e 65 73 28 31 2c 20 31 29 20 3c 3e 20 22 27 4d 69 63 72 6f 2d 56 69 72 75 73 22 20 54 68 65 6e 0d 0a 20 20 20 20 0d 0a 20 20 20 20 20 20 20 20 2e 44 65 6c 65 74 65 4c 69 6e 65 73 20 31 2c 20 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 0d 0a } //1
		$a_01_1 = {4f 75 72 63 6f 64 65 20 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 31 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 4c 69 6e 65 73 28 31 2c 20 31 30 30 29 } //1 Ourcode = ThisDocument.VBProject.VBComponents(1).CodeModule.Lines(1, 100)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}