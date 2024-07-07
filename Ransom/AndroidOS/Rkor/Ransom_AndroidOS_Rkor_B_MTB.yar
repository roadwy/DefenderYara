
rule Ransom_AndroidOS_Rkor_B_MTB{
	meta:
		description = "Ransom:AndroidOS/Rkor.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 00 00 00 71 00 90 01 02 00 00 0c 00 21 01 3d 01 14 00 12 01 21 42 35 21 10 00 48 02 04 01 21 03 94 03 01 03 48 03 00 03 b7 32 8d 22 4f 02 04 01 d8 01 01 01 28 f0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}