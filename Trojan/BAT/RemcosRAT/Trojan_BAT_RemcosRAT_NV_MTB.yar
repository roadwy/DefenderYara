
rule Trojan_BAT_RemcosRAT_NV_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 28 90 01 03 0a 9c 00 11 04 17 58 13 04 11 04 06 6f 90 01 03 0a fe 04 13 05 11 05 2d dc 90 00 } //1
		$a_01_1 = {0d 16 13 06 2b 1a 00 09 11 06 08 11 06 08 8e 69 5d 91 03 11 06 91 61 d2 9c 00 11 06 17 58 13 06 11 06 03 8e 69 fe 04 13 07 11 07 2d d9 09 13 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}