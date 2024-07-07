
rule Trojan_AndroidOS_SAgnt_AB_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 40 6e 10 90 01 02 04 00 0c 01 1f 01 90 01 02 12 02 35 02 0b 00 48 03 04 02 b7 23 8d 33 4f 03 01 02 d8 02 02 02 90 00 } //1
		$a_03_1 = {21 71 3c 01 03 00 11 00 13 02 10 00 23 23 90 01 02 b1 21 12 04 12 05 35 25 09 00 48 06 07 05 4f 06 03 05 d8 05 05 01 28 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}