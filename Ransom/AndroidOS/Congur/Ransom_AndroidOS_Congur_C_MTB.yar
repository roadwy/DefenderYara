
rule Ransom_AndroidOS_Congur_C_MTB{
	meta:
		description = "Ransom:AndroidOS/Congur.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 00 1a 01 1f 01 6e 20 ?? ?? 10 00 0a 00 38 00 18 00 6e 10 ?? ?? 02 00 22 00 0a 00 } //1
		$a_00_1 = {33 21 0f 00 54 41 07 00 44 01 01 00 87 11 13 02 2d 00 37 21 07 00 13 00 a6 ff 67 00 1b 00 } //1
		$a_03_2 = {0c 02 70 20 ?? ?? 20 00 38 04 05 00 6e 10 ?? ?? 04 00 38 03 08 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}