
rule Trojan_BAT_AsyncRAT_NAC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 11 28 0e 02 00 06 28 90 01 03 06 13 10 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 39 90 01 03 ff 26 20 90 01 03 00 38 90 01 03 ff 73 90 01 03 0a 13 02 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 3a 90 01 03 ff 26 90 00 } //5
		$a_01_1 = {51 7a 6d 6d 6f 68 6c 67 } //1 Qzmmohlg
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}