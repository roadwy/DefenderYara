
rule Trojan_BAT_AgentTesla_CAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 ?? 00 00 0a 05 03 17 58 05 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0a 2b 00 06 2a } //3
		$a_01_1 = {34 00 4b 00 42 00 58 00 53 00 38 00 34 00 45 00 39 00 46 00 34 00 51 00 35 00 58 00 42 00 48 00 47 00 58 00 42 00 35 00 35 00 34 00 } //1 4KBXS84E9F4Q5XBHGXB554
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}