
rule Trojan_Linux_Mirai_B_xp{
	meta:
		description = "Trojan:Linux/Mirai.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 6d 20 2d 72 66 20 2f 6d 6e 74 2f 6d 79 64 69 72 } //01 00 
		$a_01_1 = {68 6d 6f 64 20 37 37 37 20 2f 6d 6e 74 2f 6d 79 64 69 72 2f } //01 00 
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //01 00 
		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00 
		$a_01_4 = {59 52 46 25 36 75 64 43 4a 46 47 } //00 00 
	condition:
		any of ($a_*)
 
}