
rule Trojan_BAT_Zusy_BAC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 fe 0c 01 00 fe 0c 03 00 20 00 01 00 00 fe 0c 00 00 fe 0c 00 00 8e 69 20 01 00 00 00 59 fe 0c 03 00 59 91 58 fe 0c 02 00 59 20 00 01 00 00 5d d2 9c 00 fe 0c 03 00 20 01 00 00 00 58 fe 0e 03 00 fe 0c 03 00 fe 0c 00 00 8e 69 fe 04 fe 0e 04 00 fe 0c 04 00 3a a6 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}