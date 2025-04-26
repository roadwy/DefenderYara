
rule Trojan_BAT_AgentTesla_AACD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AACD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a } //2
		$a_01_1 = {62 00 63 00 64 00 65 00 66 00 67 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 46 00 47 00 } //1 bcdefgmnopqrstuvwxyzFG
		$a_01_2 = {44 00 61 00 74 00 61 00 42 00 61 00 73 00 65 00 50 00 72 00 61 00 63 00 74 00 69 00 63 00 61 00 6c 00 4a 00 6f 00 62 00 } //1 DataBasePracticalJob
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}