
rule Ransom_MSIL_HiddenTear_ATH_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.ATH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {15 6a 16 28 ?? 00 00 0a 17 8d ?? 00 00 01 0c 08 16 17 9e 08 28 ?? 00 00 0a 02 02 7b ?? 00 00 04 72 ?? 00 00 70 15 16 28 ?? 00 00 0a 7d ?? 00 00 04 73 ?? 00 00 06 0a 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}