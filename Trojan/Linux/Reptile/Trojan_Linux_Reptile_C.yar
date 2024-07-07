
rule Trojan_Linux_Reptile_C{
	meta:
		description = "Trojan:Linux/Reptile.C,SIGNATURE_TYPE_ELFHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_03_0 = {89 d8 31 d2 89 df 41 f7 f0 81 f7 90 01 04 83 eb 04 88 d1 d3 c7 31 3e 48 83 c6 04 83 fb 90 01 01 75 df 90 00 } //2
		$a_03_1 = {89 f0 31 d2 41 89 f0 41 f7 f1 41 81 f0 90 01 04 83 ee 04 88 d1 41 d3 c0 44 31 07 48 83 c7 04 83 fe 04 75 db 90 00 } //2
		$a_03_2 = {44 89 c8 31 d2 29 f0 89 c7 41 f7 f0 81 f7 90 01 06 d3 c7 31 be 90 01 04 48 83 c6 04 48 81 fe 90 01 04 75 d7 90 00 } //2
		$a_01_3 = {70 61 72 61 73 69 74 65 5f 62 6c 6f 62 } //10 parasite_blob
		$a_01_4 = {6b 61 6c 6c 73 79 6d 73 5f 6f 6e 5f 65 61 63 68 5f 73 79 6d 62 6f 6c } //1 kallsyms_on_each_symbol
		$a_01_5 = {6b 73 79 6d 5f 6c 6f 6f 6b 75 70 5f 63 62 } //1 ksym_lookup_cb
		$a_01_6 = {69 6e 69 74 5f 6d 6f 64 75 6c 65 } //1 init_module
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=14
 
}