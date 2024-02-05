
rule Trojan_O97M_DowMShta_B{
	meta:
		description = "Trojan:O97M/DowMShta.B,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 06 00 00 0a 00 "
		
	strings :
		$a_80_0 = {63 6d 64 20 2f 63 20 6d 73 5e } //cmd /c ms^  0a 00 
		$a_80_1 = {63 6d 64 20 2f 63 20 6d 5e } //cmd /c m^  0a 00 
		$a_80_2 = {73 74 61 72 74 20 6d 73 5e } //start ms^  0a 00 
		$a_80_3 = {73 74 61 72 74 20 6d 5e } //start m^  9c ff 
		$a_80_4 = {73 74 61 72 74 20 6d 73 68 74 61 } //start mshta  9c ff 
		$a_80_5 = {63 6d 64 20 2f 63 20 6d 73 68 74 61 } //cmd /c mshta  00 00 
	condition:
		any of ($a_*)
 
}