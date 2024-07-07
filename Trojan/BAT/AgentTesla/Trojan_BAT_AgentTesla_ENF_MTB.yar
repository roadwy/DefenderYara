
rule Trojan_BAT_AgentTesla_ENF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 5d 7e 90 01 03 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 17 58 03 8e 69 5d 91 59 20 fa 00 00 00 58 1e 58 18 59 20 00 01 00 00 5d d2 9c 08 90 00 } //1
		$a_03_1 = {2b 3a 03 08 03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 0a 03 08 17 58 03 8e 69 5d 91 59 20 fa 00 00 00 58 1e 58 18 59 20 00 01 00 00 5d d2 9c 08 17 58 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}