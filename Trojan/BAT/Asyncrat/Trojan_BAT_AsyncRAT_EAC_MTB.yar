
rule Trojan_BAT_AsyncRAT_EAC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 03 07 91 04 07 91 fe 01 16 fe 01 0c 08 39 02 00 00 00 16 0a 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 2d dc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AsyncRAT_EAC_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 11 04 9a 6f 30 00 00 0a 09 28 60 00 00 0a 13 05 11 05 2c 12 00 06 08 11 04 9a 6f 30 00 00 0a 6f 61 00 00 0a 00 00 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 06 11 06 2d c4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}