
rule Ransom_MSIL_Filecoder_SWB_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 06 16 06 8e 69 6f ?? 00 00 0a 13 09 11 09 2c 0b 11 08 06 16 11 09 6f ?? 00 00 0a 11 09 2d df } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}