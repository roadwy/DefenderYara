
rule Ransom_MSIL_Crysis_AJQA_MTB{
	meta:
		description = "Ransom:MSIL/Crysis.AJQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 02 11 05 91 07 61 11 04 06 91 61 b4 9c 1d 13 07 38 ?? ff ff ff 7e ?? 00 00 04 16 8c ?? 00 00 01 28 ?? 00 00 06 26 } //3
		$a_01_1 = {02 8e b7 17 d6 8d 5a 00 00 01 0c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}