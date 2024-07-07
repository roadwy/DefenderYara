
rule Trojan_BAT_BitRAT_NIB_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.NIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 72 9b 04 00 70 6f 90 01 02 00 0a 80 90 01 02 00 04 16 0b 2b 1b 00 7e 90 01 02 00 04 07 7e 90 01 02 00 04 07 91 20 90 01 02 00 00 59 d2 9c 00 07 17 58 0b 07 7e 90 01 02 00 04 8e 69 fe 04 0c 08 2d d7 90 00 } //5
		$a_01_1 = {5a 61 6e 6f 62 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Zanobe.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}