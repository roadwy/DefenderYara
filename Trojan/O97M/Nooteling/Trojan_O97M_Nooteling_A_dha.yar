
rule Trojan_O97M_Nooteling_A_dha{
	meta:
		description = "Trojan:O97M/Nooteling.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 22 35 30 34 62 30 33 30 34 31 34 } //01 00  = "504b030414
		$a_00_1 = {46 75 6e 63 74 69 6f 6e 20 57 72 69 74 65 42 69 6e 28 66 69 6c 65 6e 61 6d 65 2c 20 42 75 66 66 65 72 44 61 74 61 29 } //01 00  Function WriteBin(filename, BufferData)
		$a_00_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 6f 72 64 5c 53 54 41 52 54 55 50 5c } //00 00  \Microsoft\Word\STARTUP\
	condition:
		any of ($a_*)
 
}