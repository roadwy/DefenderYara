
rule DDoS_Linux_Wgcrash_A_xp{
	meta:
		description = "DDoS:Linux/Wgcrash.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 69 6e 67 61 74 65 20 63 72 61 73 68 65 72 20 62 79 20 68 6f 6c 6f 62 79 74 65 } //01 00  Wingate crasher by holobyte
		$a_01_1 = {55 73 61 67 65 3a 20 25 73 20 3c 77 69 6e 67 61 74 65 3e 20 5b 70 6f 72 74 } //01 00  Usage: %s <wingate> [port
		$a_01_2 = {43 72 61 73 68 69 6e 67 } //00 00  Crashing
	condition:
		any of ($a_*)
 
}