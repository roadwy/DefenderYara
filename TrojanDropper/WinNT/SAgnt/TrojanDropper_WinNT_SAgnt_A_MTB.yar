
rule TrojanDropper_WinNT_SAgnt_A_MTB{
	meta:
		description = "TrojanDropper:WinNT/SAgnt.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6b 49 62 77 66 30 32 6c 64 64 64 64 } //1 kIbwf02ldddd
		$a_00_1 = {67 65 74 5f 63 72 79 70 74 65 64 5f 66 69 6c 65 6e 61 6d 65 } //1 get_crypted_filename
		$a_00_2 = {4d 67 31 53 68 49 38 4f 39 54 30 36 6a 4a 51 44 72 6c 6a 73 } //1 Mg1ShI8O9T06jJQDrljs
		$a_00_3 = {4f 42 53 72 7a } //1 OBSrz
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}