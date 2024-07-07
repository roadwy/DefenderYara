
rule Trojan_BAT_LummaC_MBZS_MTB{
	meta:
		description = "Trojan:BAT/LummaC.MBZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 72 00 00 0a 07 08 6f 73 00 00 0a 13 05 28 90 01 01 00 00 06 13 06 11 06 11 05 17 73 74 00 00 0a 90 00 } //1
		$a_01_1 = {43 61 73 69 73 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}