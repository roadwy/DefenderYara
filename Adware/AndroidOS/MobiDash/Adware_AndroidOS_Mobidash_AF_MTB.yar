
rule Adware_AndroidOS_Mobidash_AF_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.AF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6d 6f 62 61 70 70 73 62 61 6b 65 72 2f 75 61 65 6f 66 66 65 72 73 } //1 com/mobappsbaker/uaeoffers
		$a_03_1 = {6e 10 b4 01 01 00 62 01 ?? 24 6e 10 b4 01 01 00 22 01 c4 00 54 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}