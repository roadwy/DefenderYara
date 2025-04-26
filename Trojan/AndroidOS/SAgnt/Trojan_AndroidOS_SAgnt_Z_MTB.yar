
rule Trojan_AndroidOS_SAgnt_Z_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0c 02 21 21 35 10 0c 00 48 01 02 00 df 01 01 3f 8d 11 4f 01 02 00 d8 00 00 01 } //3
		$a_01_1 = {63 6f 6d 2f 61 74 74 64 2f 64 61 } //1 com/attd/da
		$a_01_2 = {2f 4b 65 65 61 53 65 72 76 69 63 65 } //1 /KeeaService
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}