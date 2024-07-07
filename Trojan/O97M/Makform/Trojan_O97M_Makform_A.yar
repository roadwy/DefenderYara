
rule Trojan_O97M_Makform_A{
	meta:
		description = "Trojan:O97M/Makform.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {52 65 70 6c 61 63 65 41 6c 6c 90 01 01 2e 53 65 6e 64 90 00 } //1
		$a_02_1 = {52 65 70 6c 61 63 65 41 6c 6c 90 01 01 2e 73 61 76 65 74 6f 66 69 6c 65 20 22 66 74 7a 70 2e 65 22 20 26 20 22 78 65 22 2c 20 32 90 00 } //2
		$a_00_2 = {52 65 70 6c 61 63 65 41 6c 6c 32 2e 73 61 76 65 74 6f 66 69 6c 65 20 22 78 6c 78 2e 65 22 20 26 20 22 78 65 22 2c 20 32 } //2 ReplaceAll2.savetofile "xlx.e" & "xe", 2
		$a_00_3 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 22 4d 45 53 53 41 47 45 28 54 72 75 65 2c 20 22 22 64 61 76 69 63 68 69 } //1 ExecuteExcel4Macro "MESSAGE(True, ""davichi
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=3
 
}