
rule Trojan_BAT_StealC_NL_MTB{
	meta:
		description = "Trojan:BAT/StealC.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 21 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 0c 01 00 0a 07 1f 10 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 01 00 0a 06 07 6f 90 01 01 01 00 0a 17 90 00 } //5
		$a_01_1 = {6f 70 65 6e 73 68 6f 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 openshock.Properties.Resources
		$a_01_2 = {53 70 6c 69 74 74 79 44 65 76 } //1 SplittyDev
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}