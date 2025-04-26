
rule Trojan_BAT_AgentTesla_UEB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.UEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 5f 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 4a 00 20 07 8f fb 0e 0b 17 13 04 72 9a b4 00 70 28 ?? ?? ?? 0a 72 b8 b4 00 70 18 1b 8d 17 00 00 01 25 16 72 d2 b4 00 70 a2 25 17 20 00 01 00 00 8c 4c 00 00 01 a2 25 1a 17 8d 17 00 00 01 25 16 02 a2 a2 28 ?? ?? ?? 0a 0a 2b 00 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}