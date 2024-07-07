
rule Virus_Linux_Bansa_A{
	meta:
		description = "Virus:Linux/Bansa.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {4d 75 6c 61 42 61 6e 67 73 61 74 20 3d 20 90 02 70 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 2e 49 74 65 6d 28 22 42 61 6e 67 73 61 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 29 90 00 } //1
		$a_02_1 = {6d 61 63 61 6d 5f 6a 61 72 75 6d 40 79 61 68 6f 6f 2e 63 6f 6d 22 90 02 08 2e 45 78 65 63 75 74 65 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}