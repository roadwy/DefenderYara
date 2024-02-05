
rule Trojan_Linux_Hiddad_B_xp{
	meta:
		description = "Trojan:Linux/Hiddad.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 85 d2 48 89 34 24 0f 84 d6 04 00 00 e8 49 c6 ff ff 48 89 df e8 21 da ff ff 41 89 c4 } //01 00 
		$a_00_1 = {e8 da d0 ff ff 48 8b 13 48 89 df 48 89 c6 ff 52 30 b9 39 00 00 00 } //01 00 
		$a_00_2 = {4c 8b 44 24 18 48 89 c1 48 8b 54 24 10 48 89 df 48 8b 34 24 e8 d7 e3 ff ff e9 5d fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}