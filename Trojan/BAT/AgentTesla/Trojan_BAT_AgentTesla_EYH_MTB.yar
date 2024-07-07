
rule Trojan_BAT_AgentTesla_EYH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 06 8e 69 5d 91 90 01 05 08 91 61 d2 9c 00 08 17 58 0c 08 90 01 05 8e 69 fe 04 0d 09 2d d9 90 00 } //1
		$a_01_1 = {00 54 6f 43 68 61 72 41 72 72 61 79 00 } //1
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}