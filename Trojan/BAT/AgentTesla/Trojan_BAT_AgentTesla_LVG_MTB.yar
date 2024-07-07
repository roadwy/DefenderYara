
rule Trojan_BAT_AgentTesla_LVG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff 90 01 06 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 0b 07 0a 2b 00 06 2a 90 00 } //1
		$a_01_1 = {49 4b 4a 53 55 48 46 4e 49 55 46 48 49 55 46 48 49 55 53 46 48 49 55 46 48 49 55 53 46 49 55 53 46 48 49 55 53 46 48 } //1 IKJSUHFNIUFHIUFHIUSFHIUFHIUSFIUSFHIUSFH
		$a_03_2 = {0a 13 04 11 04 28 90 01 03 06 28 90 01 03 0a 13 05 07 11 05 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 06 11 06 2d cc 90 00 } //1
		$a_81_3 = {42 75 6e 69 66 75 5f 54 65 78 74 42 6f 78 } //1 Bunifu_TextBox
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}