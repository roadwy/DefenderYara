
rule Trojan_BAT_AgentTesla_GBN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 91 61 28 ?? ?? ?? 0a 07 09 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 08 11 08 2d b7 } //10
		$a_80_1 = {4a 45 50 34 35 57 4a 38 45 39 5a 37 48 37 37 35 34 38 37 4a 51 38 } //JEP45WJ8E9Z7H775487JQ8  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}