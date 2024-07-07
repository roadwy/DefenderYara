
rule Trojan_BAT_AgentTesla_SD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 8e 69 6a 5d d4 06 07 06 8e 69 6a 5d d4 91 08 07 08 8e 69 6a 5d d4 91 61 28 97 00 00 0a 06 07 17 6a 58 06 8e 69 6a 5d d4 91 28 98 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 99 00 00 0a 9c 07 17 6a 58 0b 07 06 8e 69 17 59 6a fe 02 16 fe 01 13 06 11 06 2d a5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}