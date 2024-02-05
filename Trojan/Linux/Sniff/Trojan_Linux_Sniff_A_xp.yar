
rule Trojan_Linux_Sniff_A_xp{
	meta:
		description = "Trojan:Linux/Sniff.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 76 61 72 2f 74 6d 70 2f 2e 66 73 5f 72 65 70 5f 73 6e 2e 6c 6f 67 } //01 00 
		$a_01_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00 
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //01 00 
		$a_01_3 = {52 45 53 53 44 41 54 45 43 4d 44 53 43 4f 4d 50 4d 4f 44 52 } //00 00 
	condition:
		any of ($a_*)
 
}