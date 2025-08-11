
rule Trojan_AndroidOS_SAgnt_CA_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.CA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 00 6e 10 81 01 00 00 0c 00 1c 01 9c 00 1a 02 03 54 12 13 23 34 3d 16 1c 05 21 0f 12 06 4d 05 04 06 6e 30 67 59 21 04 0c 01 23 32 40 16 4d 08 02 06 6e 30 d6 5a 01 02 0c 00 1f 00 f0 0e 6e 10 2b 59 00 00 0a 07 } //1
		$a_01_1 = {22 00 52 01 6e 10 0e 01 02 00 0c 01 70 20 fd 06 10 00 22 01 87 04 70 20 ed 1f 21 00 6e 20 07 07 10 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}