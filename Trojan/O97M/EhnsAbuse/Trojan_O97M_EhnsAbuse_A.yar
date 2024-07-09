
rule Trojan_O97M_EhnsAbuse_A{
	meta:
		description = "Trojan:O97M/EhnsAbuse.A,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 65 74 31 2e 41 6e 79 6b 65 79 } //1 Sheet1.Anykey
		$a_02_1 = {73 61 76 65 74 6f 66 69 6c 65 20 [0-08] 2e 65 22 20 26 20 22 78 65 22 2c 20 32 } //5
		$a_00_2 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f } //1 ExecuteExcel4Macro
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*5+(#a_00_2  & 1)*1) >=6
 
}