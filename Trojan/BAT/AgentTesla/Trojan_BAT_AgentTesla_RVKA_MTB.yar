
rule Trojan_BAT_AgentTesla_RVKA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RVKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 88 00 00 00 14 00 00 00 f9 00 00 00 83 00 00 00 8a 00 00 00 fa 00 00 00 18 00 00 00 01 00 00 00 1e 00 00 00 03 00 00 00 07 00 00 00 0a 00 00 00 04 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 0e 00 00 00 02 00 00 00 04 } //1
		$a_81_1 = {30 65 63 65 30 34 33 66 2d 39 34 36 61 2d 34 32 31 61 2d 38 61 61 62 2d 61 30 63 65 34 35 39 66 63 61 33 30 } //1 0ece043f-946a-421a-8aab-a0ce459fca30
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}