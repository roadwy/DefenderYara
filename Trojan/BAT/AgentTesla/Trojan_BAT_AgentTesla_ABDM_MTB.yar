
rule Trojan_BAT_AgentTesla_ABDM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 6f ?? ?? ?? 0a 17 9a 13 04 7e ?? ?? ?? 04 17 8d ?? ?? ?? 01 25 16 1f 25 9d 6f ?? ?? ?? 0a 13 05 11 09 90 0a 2a 00 08 28 } //2
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //1 CreateInstance
		$a_01_2 = {47 00 61 00 6d 00 65 00 5f 00 6f 00 66 00 5f 00 50 00 69 00 67 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Game_of_Pig.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}