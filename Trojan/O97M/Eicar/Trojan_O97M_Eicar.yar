
rule Trojan_O97M_Eicar{
	meta:
		description = "Trojan:O97M/Eicar,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {78 35 6f 21 70 25 40 61 70 5b 34 70 7a 78 35 34 28 70 5e 29 37 63 63 29 37 7d 24 65 69 63 61 72 2d 73 74 61 6e 64 61 72 64 2d 61 6e 74 69 76 69 72 75 73 2d 74 65 73 74 2d 66 69 6c 65 21 24 68 2b 68 2a 22 29 3b } //00 00 
		$a_00_1 = {5d 04 00 00 5b cc 04 80 5c 3d } //00 00 
	condition:
		any of ($a_*)
 
}