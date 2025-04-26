
rule Trojan_BAT_AgentTesla_NHG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 8d ?? ?? ?? 01 13 04 09 11 04 16 03 8e 69 6f ?? ?? ?? 0a 13 05 11 04 11 05 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 06 de 2c } //1
		$a_01_1 = {49 00 ce 03 c3 03 b5 03 20 00 c4 03 bf 03 bd 03 20 00 b4 03 c1 03 cc 03 bc 03 bf 03 20 00 c3 03 bf 03 c5 03 20 00 c3 } //1
		$a_01_2 = {67 65 74 5f 70 75 70 70 79 5f 62 61 72 6b } //1 get_puppy_bark
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}