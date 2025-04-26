
rule Ransom_AndroidOS_Boogr_A_MTB{
	meta:
		description = "Ransom:AndroidOS/Boogr.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 02 60 03 69 00 35 03 2d 00 54 42 ?? 08 6e 10 ?? ?? 02 00 0a 02 3c 02 06 00 5c 41 ?? 08 12 00 } //1
		$a_03_1 = {0c 00 1a 01 ?? ?? 12 32 23 22 e0 05 13 03 34 00 12 04 4f 03 02 04 13 03 0f 00 12 15 4f 03 02 05 12 23 12 76 4f 06 02 03 71 20 ?? ?? 21 00 0c 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}