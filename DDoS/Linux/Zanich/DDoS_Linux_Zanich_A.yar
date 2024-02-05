
rule DDoS_Linux_Zanich_A{
	meta:
		description = "DDoS:Linux/Zanich.A,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 6e 74 20 53 65 72 76 65 72 2e 2e 2e 00 43 68 69 6e 61 5a 00 63 6f 6e 6e 65 63 74 20 74 6f 20 73 65 72 76 65 72 2e 2e 2e 00 } //01 00 
		$a_00_1 = {73 65 64 20 2d 69 20 2d 65 20 27 32 20 69 25 73 2f 25 73 27 20 2f 65 74 63 2f 72 63 2e 6c 6f 63 61 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}