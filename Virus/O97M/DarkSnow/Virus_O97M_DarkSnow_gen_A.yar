
rule Virus_O97M_DarkSnow_gen_A{
	meta:
		description = "Virus:O97M/DarkSnow.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 72 75 6e 62 6c 61 63 6b 69 63 65 28 29 } //1 Private Sub runblackice()
		$a_00_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 57 72 69 74 65 46 69 6c 65 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 } //1 Private Declare Function WriteFile Lib "kernel32"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}