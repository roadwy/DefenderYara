
rule Trojan_O97M_FinDropper_H_dha{
	meta:
		description = "Trojan:O97M/FinDropper.H!dha,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 28 22 44 6f 63 75 6d 65 6e 74 20 64 65 63 72 79 70 74 20 65 72 72 6f 72 2e 22 29 } //1 MsgBox ("Document decrypt error.")
		$a_02_1 = {55 73 65 72 46 6f 72 6d 31 2e [0-0a] 2e 43 61 70 74 69 6f 6e } //1
		$a_02_2 = {43 68 44 69 72 20 [0-0a] 4f 70 65 6e } //1
		$a_02_3 = {3d 20 49 6e 53 74 72 28 [0-10] 2c 22 3b 3b 22 29 } //1
		$a_02_4 = {46 6f 72 20 69 20 3d 20 [0-0a] 20 54 6f 20 [0-0a] 3a 20 [0-0a] 20 3d 20 [0-0a] 20 26 20 [0-0a] 3a 20 4e 65 78 74 } //1
		$a_02_5 = {4f 70 65 6e 20 [0-10] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 39 3a 20 50 72 69 6e 74 20 23 31 39 2c 20 [0-10] 3a 20 43 6c 6f 73 65 20 23 31 39 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=4
 
}