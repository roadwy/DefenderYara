
rule DDoS_Linux_Zanich_C{
	meta:
		description = "DDoS:Linux/Zanich.C,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 2e 44 44 6f 73 43 6c 69 65 6e 74 55 70 64 61 74 65 72 2e 73 6f 63 6b 00 } //01 00 
		$a_00_1 = {6d 76 20 44 44 6f 73 43 6c 69 65 6e 74 2e 62 61 63 6b 20 44 44 6f 73 43 6c 69 65 6e 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}