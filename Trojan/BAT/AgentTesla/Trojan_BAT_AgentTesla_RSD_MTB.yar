
rule Trojan_BAT_AgentTesla_RSD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 9e 00 00 00 2b 00 00 00 05 01 00 00 45 01 00 00 64 01 00 00 57 01 00 00 42 00 00 00 01 00 00 00 55 00 00 00 03 00 00 00 07 00 00 00 09 00 00 00 13 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 1b 00 00 00 03 00 00 00 04 } //1
		$a_81_1 = {39 63 36 32 35 31 64 63 2d 36 61 39 33 2d 34 38 62 62 2d 62 63 63 66 2d 65 31 38 37 34 32 30 30 35 38 63 61 } //1 9c6251dc-6a93-48bb-bccf-e187420058ca
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}