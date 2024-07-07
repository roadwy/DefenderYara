
rule Trojan_BAT_Dcstl_NP_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 28 a5 00 00 0a 25 28 90 01 03 0a 6f 90 01 03 0a 25 74 90 01 03 01 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 90 00 } //5
		$a_01_1 = {43 00 68 00 61 00 6f 00 61 00 70 00 } //1 Chaoap
		$a_01_2 = {47 43 6c 65 61 6e 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 GCleaner.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}