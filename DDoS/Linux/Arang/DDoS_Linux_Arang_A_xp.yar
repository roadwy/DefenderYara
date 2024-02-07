
rule DDoS_Linux_Arang_A_xp{
	meta:
		description = "DDoS:Linux/Arang.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 6f 53 20 62 79 20 41 72 63 68 41 6e 67 33 } //01 00  DoS by ArchAng3
		$a_01_1 = {69 6e 65 74 64 5f 44 6f 53 2e 63 } //01 00  inetd_DoS.c
		$a_01_2 = {30 66 20 44 65 61 74 68 20 2d 20 4d 65 6d 62 65 72 } //00 00  0f Death - Member
	condition:
		any of ($a_*)
 
}