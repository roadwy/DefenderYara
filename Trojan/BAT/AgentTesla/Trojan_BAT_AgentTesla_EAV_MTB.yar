
rule Trojan_BAT_AgentTesla_EAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1f 00 07 08 02 08 91 6e 08 06 5d 28 90 01 01 00 00 06 6a 59 20 ff 00 00 00 6a 5f d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 04 11 04 2d d5 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_EAV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 21 11 04 06 07 6f 90 01 03 0a 13 05 11 05 28 90 01 03 0a 13 06 09 11 06 d2 6f 90 01 03 0a 07 17 58 0b 07 17 fe 04 13 07 11 07 2d d5 08 17 58 0c 06 17 58 0a 90 00 } //1
		$a_01_1 = {00 54 6f 57 69 6e 33 32 00 } //1
		$a_01_2 = {00 47 65 74 50 69 78 65 6c 00 } //1 䜀瑥楐數l
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}