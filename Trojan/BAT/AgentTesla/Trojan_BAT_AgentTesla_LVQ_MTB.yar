
rule Trojan_BAT_AgentTesla_LVQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 90 01 03 06 28 90 01 03 0a 13 05 07 11 05 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 06 11 06 2d cc 90 00 } //1
		$a_03_1 = {02 6c 23 ff b9 f4 ee 2a 81 f7 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 0b 07 0a 90 00 } //1
		$a_01_2 = {41 4a 44 48 49 55 4a 44 48 55 49 41 44 48 49 55 41 44 48 41 44 49 55 48 44 55 49 48 41 } //1 AJDHIUJDHUIADHIUADHADIUHDUIHA
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}