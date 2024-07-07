
rule Trojan_AndroidOS_SpyNote_TA_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyNote.TA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 03 12 45 1a 01 35 01 71 10 98 02 01 00 0a 01 2b 01 90 01 02 00 00 12 11 01 12 01 54 07 01 21 06 98 00 05 04 d8 00 00 ff df 04 00 20 32 62 90 01 02 49 00 01 02 95 05 08 04 b7 05 d8 08 08 ff d8 00 02 01 8e 55 50 05 01 02 01 02 28 f1 71 30 c7 02 31 06 0c 00 6e 10 b5 02 00 00 0c 00 11 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}