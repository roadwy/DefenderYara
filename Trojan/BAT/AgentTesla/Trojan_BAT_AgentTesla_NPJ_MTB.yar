
rule Trojan_BAT_AgentTesla_NPJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 20 00 14 01 00 5d 07 11 04 20 00 14 01 00 5d 91 08 11 04 1f 16 5d 6f 90 01 03 0a 61 07 11 04 17 58 20 00 14 01 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d b0 90 00 } //1
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 } //1 GetObject
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}