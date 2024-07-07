
rule Trojan_Linux_Turla_E{
	meta:
		description = "Trojan:Linux/Turla.E,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_80_0 = {2e 2f 61 20 66 69 6c 65 6e 61 6d 65 20 74 65 6d 70 6c 61 74 65 5f 66 69 6c 65 } //./a filename template_file  1
		$a_80_1 = {4d 61 79 20 62 65 20 25 73 20 69 73 20 65 6d 70 74 79 3f } //May be %s is empty?  1
		$a_80_2 = {74 65 6d 70 6c 61 74 65 20 73 74 72 69 6e 67 20 3d 20 7c 25 73 7c } //template string = |%s|  1
		$a_80_3 = {4e 6f 20 62 6c 6f 63 6b 73 20 21 21 21 } //No blocks !!!  1
		$a_80_4 = {4e 6f 20 64 61 74 61 20 69 6e 20 74 68 69 73 20 62 6c 6f 63 6b 20 21 21 21 21 21 21 } //No data in this block !!!!!!  1
		$a_80_5 = {4e 6f 20 67 6f 6f 64 20 6c 69 6e 65 } //No good line  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=3
 
}