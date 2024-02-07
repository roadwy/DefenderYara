
rule DDoS_Linux_Flooder_I_xp{
	meta:
		description = "DDoS:Linux/Flooder.I!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 25 73 20 3c 74 61 72 67 65 74 20 49 50 3e } //01 00  Usage: %s <target IP>
		$a_01_1 = {49 53 53 59 4e } //01 00  ISSYN
		$a_01_2 = {46 6c 6f 6f 64 69 6e 67 3a 20 25 73 } //01 00  Flooding: %s
		$a_01_3 = {53 74 61 72 74 20 66 6c 6f 6f 64 69 6e 67 20 2e 2e 2e } //00 00  Start flooding ...
		$a_00_4 = {5d 04 00 00 } //d5 0f 
	condition:
		any of ($a_*)
 
}