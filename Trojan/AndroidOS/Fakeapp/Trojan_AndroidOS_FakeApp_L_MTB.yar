
rule Trojan_AndroidOS_FakeApp_L_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3b 00 08 00 22 00 90 02 06 50 00 11 00 d8 06 02 ff 6e 20 90 01 02 28 00 0a 00 6e 20 90 01 02 34 00 0a 07 b7 70 df 00 00 90 01 02 00 50 00 05 02 3a 06 ea ff 6e 20 ee 46 68 00 0a 00 6e 20 90 01 02 34 00 0a 02 b7 20 df 00 90 01 02 8e 07 d8 02 06 ff d8 00 03 ff 50 07 05 06 3b 00 03 00 01 10 01 03 01 20 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}