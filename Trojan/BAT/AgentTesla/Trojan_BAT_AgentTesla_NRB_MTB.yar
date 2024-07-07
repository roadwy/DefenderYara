
rule Trojan_BAT_AgentTesla_NRB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {20 00 60 00 00 5d 91 08 09 1f 16 5d 28 90 01 03 06 61 07 09 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 90 00 } //1
		$a_01_1 = {51 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //1 Q___________________
		$a_01_2 = {57 41 53 57 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 } //1 WASWDDDDDDDDDDDDDDDDDDDDDDDDDDDD
		$a_01_3 = {57 52 45 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 } //1 WRECCCCCCCCCCCCCCCCCCCCCCC
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}