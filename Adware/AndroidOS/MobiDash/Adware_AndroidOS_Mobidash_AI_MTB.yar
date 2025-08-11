
rule Adware_AndroidOS_Mobidash_AI_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.AI!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 54 00 0c 04 21 45 01 26 35 56 11 00 46 07 04 06 6e 10 ?? 43 07 00 1a 08 } //1
		$a_03_1 = {12 00 6e 20 50 01 03 00 0c 00 1a 01 ?? 7e 1a 02 00 00 72 30 73 03 10 02 0c 00 1a 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}