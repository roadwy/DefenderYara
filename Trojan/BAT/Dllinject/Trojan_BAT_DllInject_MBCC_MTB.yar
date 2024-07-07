
rule Trojan_BAT_DllInject_MBCC_MTB{
	meta:
		description = "Trojan:BAT/DllInject.MBCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 5b 33 49 06 1e 58 11 05 1f 5d 6f 90 01 01 00 00 0a 54 11 05 17 06 1e 58 4a 17 59 6f 90 01 01 00 00 0a 25 1f 7a 6f 86 00 00 0a 16 fe 04 16 fe 01 13 06 1f 74 6f 90 01 01 00 00 0a 16 fe 04 16 fe 01 13 07 11 05 06 1e 58 4a 90 00 } //1
		$a_01_1 = {41 73 6b 67 6c 71 65 6e 6c 68 75 } //1 Askglqenlhu
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}