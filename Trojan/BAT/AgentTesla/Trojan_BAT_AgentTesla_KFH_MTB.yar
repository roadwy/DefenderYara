
rule Trojan_BAT_AgentTesla_KFH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 47 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 32 00 20 07 8f fb 0e 0b 17 13 04 d0 68 00 00 01 28 90 01 03 0a 72 bb e8 01 70 20 00 01 00 00 14 14 17 8d 17 00 00 01 25 16 02 a2 28 90 01 03 0a 0a 2b 00 06 2a 90 00 } //1
		$a_01_1 = {54 00 72 00 61 00 6e 00 73 00 6c 00 61 00 74 00 6f 00 72 00 } //1 Translator
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}