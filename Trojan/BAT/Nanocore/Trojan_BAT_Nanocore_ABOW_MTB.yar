
rule Trojan_BAT_Nanocore_ABOW_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABOW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 9a 1f 10 28 90 01 03 06 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc 90 00 } //5
		$a_01_1 = {53 70 6c 69 74 } //1 Split
		$a_01_2 = {57 00 65 00 62 00 73 00 69 00 74 00 65 00 52 00 65 00 76 00 69 00 65 00 77 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WebsiteReviewSimulation.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}