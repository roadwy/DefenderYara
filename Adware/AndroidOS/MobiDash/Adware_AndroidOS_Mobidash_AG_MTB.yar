
rule Adware_AndroidOS_Mobidash_AG_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.AG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {65 00 14 06 1c 00 0d 7f 6e 20 ?? 11 65 00 6e 10 ?? 15 05 00 0c 06 5b 56 } //1
		$a_03_1 = {96 14 06 b8 00 0a 7f 6e 20 ?? 11 65 00 0c 06 5b 56 ?? 96 14 06 9d 02 0a 7f 6e 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}