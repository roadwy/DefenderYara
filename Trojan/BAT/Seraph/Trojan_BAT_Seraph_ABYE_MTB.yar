
rule Trojan_BAT_Seraph_ABYE_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ABYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 16 2c 03 26 2b 2c 0a 2b fb 00 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 1a 2d 09 26 12 00 1e 2d 06 26 de 0d 0a 2b f5 28 90 01 01 00 00 06 2b f4 26 de 00 06 2c d4 90 00 } //4
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 37 00 35 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsFormsApp75.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}