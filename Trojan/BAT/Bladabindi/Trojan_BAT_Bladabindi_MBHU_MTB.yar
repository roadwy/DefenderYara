
rule Trojan_BAT_Bladabindi_MBHU_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {22 00 00 40 41 16 19 16 73 2e 00 00 0a 6f 90 01 01 00 00 0a 00 02 7b 2e 00 00 04 20 4a 01 00 00 20 4e 02 00 00 90 00 } //1
		$a_01_1 = {61 32 37 30 2d 35 35 64 33 62 30 62 38 63 65 30 66 } //1 a270-55d3b0b8ce0f
		$a_01_2 = {43 4d 5f 4c 69 6e 6b 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 CM_Links.Properties.Resources.resource
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}