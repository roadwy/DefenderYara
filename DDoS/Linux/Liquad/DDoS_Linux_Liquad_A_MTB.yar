
rule DDoS_Linux_Liquad_A_MTB{
	meta:
		description = "DDoS:Linux/Liquad.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 ba 04 00 00 00 00 00 00 00 b9 00 40 00 00 b8 00 00 00 00 48 bf 00 08 00 00 00 00 00 00 4c 8d 85 90 01 02 ff ff 48 89 bd 90 01 02 ff ff 4c 89 c7 48 89 b5 90 01 02 ff ff 89 c6 4c 8b 85 90 01 02 ff ff 48 89 95 90 01 02 ff ff 4c 89 c2 89 8d 90 01 02 ff ff e8 90 01 02 ff ff 8b 7d 90 01 01 48 8b b5 90 01 02 ff ff 48 8b 95 90 01 02 ff ff 8b 8d 90 01 02 ff ff e8 90 01 02 ff ff 90 00 } //01 00 
		$a_00_1 = {25 63 5d 30 3b 42 6f 74 73 20 63 6f 6e 6e 65 63 74 65 64 3a 20 25 64 20 7c 20 43 6c 69 65 6e 74 73 20 63 6f 6e 6e 65 63 74 65 64 3a 20 25 64 25 63 } //01 00 
		$a_00_2 = {4c 4f 4c 4e 4f 47 54 46 4f } //00 00 
	condition:
		any of ($a_*)
 
}