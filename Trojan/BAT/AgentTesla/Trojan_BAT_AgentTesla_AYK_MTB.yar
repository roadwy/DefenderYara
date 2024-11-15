
rule Trojan_BAT_AgentTesla_AYK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 03 33 06 07 04 fe 01 2b 01 16 0c 08 2c 03 00 2b 01 00 07 17 58 0b 07 02 7b 0f 00 00 04 6f ?? ?? ?? 06 fe 04 0d 09 2d d6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AYK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {48 4e 2e 50 72 6f 64 75 63 74 2e 72 65 73 6f 75 72 63 65 73 } //2 HN.Product.resources
		$a_81_1 = {24 63 34 32 39 35 38 31 35 2d 66 63 63 34 2d 34 33 30 37 2d 39 35 65 32 2d 66 39 36 39 31 62 63 37 66 62 65 33 } //2 $c4295815-fcc4-4307-95e2-f9691bc7fbe3
		$a_81_2 = {45 62 76 73 4f 43 63 4f 42 5a 68 7a 71 61 48 } //2 EbvsOCcOBZhzqaH
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}