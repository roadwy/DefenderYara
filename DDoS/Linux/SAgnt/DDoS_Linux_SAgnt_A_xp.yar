
rule DDoS_Linux_SAgnt_A_xp{
	meta:
		description = "DDoS:Linux/SAgnt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 32 43 44 44 6f 73 55 44 50 54 61 73 6b } //01 00  12CDDosUDPTask
		$a_01_1 = {31 32 43 44 44 6f 73 53 79 6e 54 61 73 6b } //01 00  12CDDosSynTask
		$a_01_2 = {31 31 43 44 44 6f 73 43 43 54 61 73 6b } //01 00  11CDDosCCTask
		$a_01_3 = {73 79 6e 20 64 64 6f 73 20 74 61 73 6b 20 66 69 6e 69 73 68 65 64 } //00 00  syn ddos task finished
	condition:
		any of ($a_*)
 
}