
rule Virus_O97M_Ramnit_A{
	meta:
		description = "Virus:O97M/Ramnit.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 72 6f 70 46 69 6c 65 4e 61 6d 65 20 3d 20 22 77 64 65 78 70 6c 6f 72 65 2e 65 78 65 22 0d 0a 44 69 6d 20 57 72 69 74 65 41 72 72 61 79 28 [0-05] 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 57 72 69 74 65 41 72 72 61 79 28 31 29 20 3d 20 22 34 44 35 41 39 30 30 30 30 33 30 30 30 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}