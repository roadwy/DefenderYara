
rule Trojan_Linux_Mircforce_A_xp{
	meta:
		description = "Trojan:Linux/Mircforce.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 48 45 3a 6d 49 52 4b 66 4f 52 43 45 } //02 00 
		$a_01_1 = {73 2f 69 72 63 6e 65 74 2f 6d 69 72 6b 6e 65 74 2f } //01 00 
		$a_01_2 = {64 65 66 2e 66 6c 6f 6f 64 } //01 00 
		$a_01_3 = {52 41 57 20 69 52 43 4c 69 4e 45 } //01 00 
		$a_01_4 = {2e 3a 74 48 61 20 6c 45 45 74 66 30 72 43 65 3a 2e } //00 00 
	condition:
		any of ($a_*)
 
}