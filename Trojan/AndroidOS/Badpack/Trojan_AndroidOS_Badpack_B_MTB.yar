
rule Trojan_AndroidOS_Badpack_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Badpack.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {71 40 bc 01 99 99 0a 09 35 98 0f 00 21 59 35 98 0c 00 48 09 05 08 d7 99 54 00 8d 99 4f 09 05 08 d8 08 08 01 } //1
		$a_01_1 = {b7 65 38 04 0a 00 1b 07 00 01 00 00 71 10 da 01 07 00 0c 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}