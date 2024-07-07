
rule Trojan_AndroidOS_Opfake_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 01 00 00 1a 03 01 00 07 24 07 25 74 06 07 00 00 00 1a 01 04 00 1a 03 01 00 07 24 07 25 74 06 07 00 00 00 1a 01 04 00 1a 03 01 00 07 24 07 25 74 06 07 00 00 00 1a 01 03 00 1a 03 01 00 07 24 07 25 } //1
		$a_01_1 = {12 0a 12 02 6f 20 01 00 cb 00 15 01 03 7f 6e 20 15 00 1b 00 22 08 18 00 1a 01 40 00 1a 03 47 00 70 30 1c 00 18 03 6e 10 1d 00 08 00 0a 01 38 01 05 00 71 10 24 00 0a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}