
rule Trojan_BAT_AgentTesla_SKF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 64 75 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Product.Properties.Resources
		$a_81_1 = {2f 2f 31 36 37 2e 31 36 30 2e 31 36 36 2e 32 30 35 2f 31 35 37 31 2e 62 69 6e } //1 //167.160.166.205/1571.bin
		$a_00_2 = {00 7e 08 00 00 04 06 7e 08 00 00 04 06 91 20 23 06 00 00 59 d2 9c 00 06 17 58 0a 06 7e 08 00 00 04 8e 69 fe 04 0b 07 2d d7 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SKF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 02 06 07 28 f0 00 00 06 0c 04 03 6f f6 00 00 0a 59 0d 03 08 09 28 f2 00 00 06 00 03 08 09 28 f4 00 00 06 00 03 04 28 f5 00 00 06 00 00 07 17 58 0b 07 02 6f f7 00 00 0a fe 04 13 04 11 04 2d bf } //1
		$a_01_1 = {43 6f 6e 42 6f 6f 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 ConBook.Properties.Resources
		$a_01_2 = {43 6f 6e 42 6f 6f 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ConBook.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}