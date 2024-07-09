
rule Trojan_BAT_AgentTesla_MBFB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 11 ?? 91 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MBFB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 03 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 2a } //1
		$a_01_1 = {35 65 38 62 35 62 39 36 34 31 39 30 } //1 5e8b5b964190
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBFB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 11 [0-07] 91 59 20 00 01 00 00 58 20 00 01 00 00 5d } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}