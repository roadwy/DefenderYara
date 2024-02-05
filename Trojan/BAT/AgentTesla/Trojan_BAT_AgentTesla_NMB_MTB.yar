
rule Trojan_BAT_AgentTesla_NMB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {6b 6f 74 61 64 69 61 69 6e 63 2e 63 6f 6d 2f 56 66 69 63 63 6c 73 69 6e 2e 6a 70 67 } //kotadiainc.com/Vficclsin.jpg  01 00 
		$a_01_1 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 32 00 30 } //01 00 
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00 
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00 
		$a_80_4 = {52 65 76 65 72 73 65 } //Reverse  00 00 
	condition:
		any of ($a_*)
 
}