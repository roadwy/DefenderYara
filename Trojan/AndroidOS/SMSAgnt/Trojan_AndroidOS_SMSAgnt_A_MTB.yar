
rule Trojan_AndroidOS_SMSAgnt_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SMSAgnt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {60 00 30 00 13 01 16 00 34 10 4e 00 13 00 c5 00 13 01 61 00 13 02 23 00 71 30 90 01 02 10 02 0c 00 71 20 90 01 02 06 00 0a 00 38 00 3e 00 13 00 70 00 13 01 74 00 13 02 1e 00 71 30 90 01 02 10 02 0c 00 6e 20 90 01 02 06 00 0c 00 1f 00 9e 00 07 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}