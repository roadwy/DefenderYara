
rule Ransom_MSIL_Filecoder_NITD_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.NITD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 07 09 16 11 05 6f ?? 00 00 0a 26 16 13 06 38 11 00 00 00 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 3f e5 ff ff ff 28 ?? 00 00 0a 09 6f ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}