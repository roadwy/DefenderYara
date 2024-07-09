
rule Trojan_BAT_AgentTesla_EOV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 0b 11 08 11 0b e0 58 13 08 11 08 1f 10 58 4b 13 0c 11 08 1f 14 58 4b 13 0d 11 08 11 0b e0 59 13 08 11 0c } //1
		$a_03_1 = {06 07 02 07 91 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 00 07 17 58 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_EOV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EOV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 60 00 00 5d 07 09 20 00 60 00 00 5d 91 08 09 1f 16 5d ?? ?? ?? ?? ?? 61 07 09 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 } //1
		$a_03_1 = {07 09 20 00 36 00 00 5d 07 09 20 00 36 00 00 5d 91 08 09 1f 16 5d ?? ?? ?? ?? ?? 61 07 09 17 58 20 00 36 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 09 15 58 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}