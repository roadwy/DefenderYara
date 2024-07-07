
rule Trojan_AndroidOS_FakeSMS_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeSMS.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 03 71 00 0d 00 00 00 0c 00 22 01 06 00 1a 02 90 01 01 00 70 20 05 00 21 00 71 40 03 00 36 31 0c 04 22 01 06 00 1a 02 90 01 01 00 70 20 05 00 21 00 71 40 03 00 36 31 0c 05 12 02 07 71 07 83 74 06 0e 00 00 00 0e 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}