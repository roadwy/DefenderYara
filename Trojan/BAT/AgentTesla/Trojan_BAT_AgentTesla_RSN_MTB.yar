
rule Trojan_BAT_AgentTesla_RSN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 15 a2 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5b 00 00 00 08 00 00 00 1f 00 00 00 30 00 00 00 30 00 00 00 8b 00 00 00 1e 00 00 00 14 00 00 00 03 00 00 00 06 00 00 00 09 00 00 00 03 00 00 00 01 00 00 00 08 00 00 00 04 00 00 00 02 } //1
		$a_81_1 = {33 36 30 33 31 66 65 32 2d 35 33 36 65 2d 34 34 62 37 2d 61 65 34 64 2d 31 66 36 38 30 66 36 38 30 33 32 66 } //1 36031fe2-536e-44b7-ae4d-1f680f68032f
		$a_81_2 = {50 72 6f 6a 65 63 74 5f 43 61 6c 65 6e 64 61 72 } //1 Project_Calendar
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}