
rule Ransom_MSIL_Filecoder_SWY_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SWY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 25 13 05 16 31 38 09 11 04 16 11 05 6f ?? 00 00 0a 07 6f ?? 00 00 0a 16 6a 31 23 06 07 6f ?? 00 00 0a 65 17 6f ?? 00 00 0a 26 06 07 6f ?? 00 00 0a 16 07 6f ?? 00 00 0a 69 6f ?? 00 00 0a 11 05 16 30 b0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}