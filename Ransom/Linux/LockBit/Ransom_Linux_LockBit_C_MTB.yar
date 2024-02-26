
rule Ransom_Linux_LockBit_C_MTB{
	meta:
		description = "Ransom:Linux/LockBit.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 81 6a 75 64 00 31 d0 88 81 6a 75 64 00 48 83 c1 01 84 c0 75 e9 } //01 00 
		$a_00_1 = {0f b6 04 31 0f b6 14 39 48 01 d0 4c 01 c8 88 04 39 49 89 c1 48 83 c1 01 49 c1 e9 08 4c 39 c1 75 df } //01 00 
		$a_00_2 = {ba ff ff ff ff be 01 00 00 00 48 89 ef e8 c1 fd fe ff 85 c0 79 2c 41 8b 04 24 83 f8 04 74 e1 83 f8 0b 74 dc } //00 00 
	condition:
		any of ($a_*)
 
}