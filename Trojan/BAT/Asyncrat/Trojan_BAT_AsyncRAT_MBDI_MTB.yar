
rule Trojan_BAT_AsyncRAT_MBDI_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 0d 00 07 08 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 00 07 18 6f 90 01 01 01 00 0a 00 07 6f 90 01 01 01 00 0a 13 04 02 13 05 11 04 11 05 16 11 05 8e 69 6f 90 01 01 01 00 0a 0a de 28 90 00 } //1
		$a_01_1 = {66 37 37 61 31 34 39 36 32 61 39 66 } //1 f77a14962a9f
		$a_01_2 = {41 73 79 6e 63 52 41 54 } //1 AsyncRAT
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}