
rule Trojan_BAT_AgentTesla_NZW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? 00 00 0a 00 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d4 } //1
		$a_81_1 = {79 65 73 73 75 72 65 31 32 33 32 31 } //1 yessure12321
		$a_81_2 = {6d 61 6b 65 66 69 6c 2e 6d 61 6b 65 66 69 6c } //1 makefil.makefil
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}