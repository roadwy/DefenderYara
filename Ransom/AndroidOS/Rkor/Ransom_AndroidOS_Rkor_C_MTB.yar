
rule Ransom_AndroidOS_Rkor_C_MTB{
	meta:
		description = "Ransom:AndroidOS/Rkor.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 00 09 00 54 21 ?? 0c 33 13 05 00 72 20 ?? ?? 20 00 } //1
		$a_03_1 = {00 39 00 23 00 1c 00 ?? 02 1d 00 62 00 ?? 00 39 00 13 00 22 00 ?? 02 62 01 ?? 00 38 01 03 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}