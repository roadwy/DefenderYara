
rule DDoS_Linux_Zanich_B{
	meta:
		description = "DDoS:Linux/Zanich.B,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 4b 33 32 20 53 65 63 75 72 74 44 6f 6f 72 00 } //01 00 
		$a_00_1 = {4d 4b 36 34 20 53 65 63 75 72 74 44 6f 6f 72 00 } //04 00 
		$a_00_2 = {44 64 6f 73 20 41 54 54 41 43 45 21 } //04 00 
		$a_00_3 = {43 4f 4d 4d 41 4e 44 5f 44 44 4f 53 5f 53 54 4f 50 } //00 00 
	condition:
		any of ($a_*)
 
}