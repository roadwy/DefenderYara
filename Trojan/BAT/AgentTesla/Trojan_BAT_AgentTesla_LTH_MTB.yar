
rule Trojan_BAT_AgentTesla_LTH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 26 00 08 09 11 04 28 ?? ?? ?? 06 13 07 11 07 28 ?? ?? ?? 0a 13 08 07 11 08 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 09 11 09 2d cf } //1
		$a_01_1 = {00 4d 38 33 00 } //1
		$a_01_2 = {00 4d 38 34 00 } //1
		$a_01_3 = {00 4d 38 35 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}