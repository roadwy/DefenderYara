
rule Trojan_Linux_Xarcen_B_xp{
	meta:
		description = "Trojan:Linux/Xarcen.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 24 08 7a 2c 0b 08 8b 45 f8 89 44 24 04 c7 04 24 83 2c 0b 08 e8 7c 04 00 00 } //1
		$a_00_1 = {83 7d f8 05 7e ae 8b 45 fc 89 44 24 08 c7 44 24 04 1e 2d 0b 08 } //1
		$a_00_2 = {e8 21 02 00 00 c7 44 24 08 24 2d 0b 08 8b 45 fc 89 44 24 04 c7 04 24 83 2c 0b 08 e8 06 02 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}