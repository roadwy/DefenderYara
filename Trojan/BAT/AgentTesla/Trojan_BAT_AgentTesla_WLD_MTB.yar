
rule Trojan_BAT_AgentTesla_WLD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 03 06 1a 58 4a 17 58 03 8e 69 5d 91 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_2 = {54 6f 49 6e 74 33 32 } //1 ToInt32
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}