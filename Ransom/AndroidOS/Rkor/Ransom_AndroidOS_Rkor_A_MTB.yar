
rule Ransom_AndroidOS_Rkor_A_MTB{
	meta:
		description = "Ransom:AndroidOS/Rkor.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 00 21 41 35 10 18 00 48 01 04 00 71 00 ?? ?? 00 00 0c 02 71 00 ?? ?? 00 00 0c 03 21 33 94 03 00 03 48 02 02 03 b7 21 8d 11 4f 01 04 00 d8 00 00 01 28 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}