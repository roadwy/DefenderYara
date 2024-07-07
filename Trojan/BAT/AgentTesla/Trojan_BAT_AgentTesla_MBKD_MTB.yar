
rule Trojan_BAT_AgentTesla_MBKD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 0a 03 04 17 58 06 5d 91 0b 2b 00 07 2a } //1
		$a_01_1 = {24 33 33 32 32 33 66 34 32 2d 34 30 33 61 2d 34 66 34 36 2d 38 32 63 38 2d 37 36 31 35 36 66 65 33 37 30 65 38 } //1 $33223f42-403a-4f46-82c8-76156fe370e8
		$a_01_2 = {4a 65 6f 70 61 72 64 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 } //1 Jeopardy.Properties.Resources.resourc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}