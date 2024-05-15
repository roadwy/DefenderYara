
rule Trojan_Linux_RudeDevil_B_MTB{
	meta:
		description = "Trojan:Linux/RudeDevil.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 61 6c 77 69 74 68 44 44 6f 53 } //01 00  DealwithDDoS
		$a_01_1 = {57 5a 55 64 70 5f 46 6c 6f 6f 64 } //01 00  WZUdp_Flood
		$a_01_2 = {43 43 41 74 74 61 63 6b } //01 00  CCAttack
		$a_01_3 = {49 43 4d 50 46 6c 6f 6f 64 } //01 00  ICMPFlood
		$a_01_4 = {54 43 50 5f 46 6c 6f 6f 64 } //00 00  TCP_Flood
	condition:
		any of ($a_*)
 
}