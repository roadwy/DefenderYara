
rule Virus_Linux_Thebe{
	meta:
		description = "Virus:Linux/Thebe,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {93 e8 3f 00 00 00 3d 7f 45 4c 46 74 03 31 c0 c3 } //1
		$a_01_1 = {52 53 42 52 42 42 52 51 31 } //1 RSBRBBRQ1
		$a_01_2 = {8b 30 01 fe 8b 16 81 fa 2e 64 74 6f 74 05 e2 e8 31 c0 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}