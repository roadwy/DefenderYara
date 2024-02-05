
rule DDoS_Linux_Flooder_B_xp{
	meta:
		description = "DDoS:Linux/Flooder.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 44 24 3c b8 94 a4 04 08 c7 44 24 08 05 00 00 00 89 44 24 04 8d 44 24 14 89 04 24 e8 e8 e5 ff ff 8d 44 24 14 89 44 24 08 c7 44 24 04 15 89 00 00 8b 44 24 3c 89 04 24 e8 ac e5 ff ff 85 c0 79 18 c7 04 24 bd a4 04 08 } //01 00 
		$a_00_1 = {b8 e4 a1 04 08 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 8d 44 24 34 89 04 24 e8 d5 e5 ff ff b8 3d a2 04 08 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 c7 04 24 7c b9 04 08 } //00 00 
	condition:
		any of ($a_*)
 
}