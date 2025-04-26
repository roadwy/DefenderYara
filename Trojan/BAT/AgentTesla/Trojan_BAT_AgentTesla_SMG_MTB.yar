
rule Trojan_BAT_AgentTesla_SMG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 53 00 00 06 0a 06 02 7d a3 00 00 04 00 16 06 7b a3 00 00 04 6f 54 00 00 0a 18 5b 28 55 00 00 0a 06 fe 06 54 00 00 06 73 56 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 0b 2b 00 07 2a } //1
		$a_81_1 = {24 61 39 34 32 62 37 32 38 2d 66 63 35 64 2d 34 63 63 36 2d 62 62 65 38 2d 65 39 30 38 61 66 31 63 32 31 31 33 } //1 $a942b728-fc5d-4cc6-bbe8-e908af1c2113
		$a_81_2 = {34 44 35 41 39 30 30 30 30 33 7e 7e 30 34 7e 7e } //1 4D5A900003~~04~~
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}