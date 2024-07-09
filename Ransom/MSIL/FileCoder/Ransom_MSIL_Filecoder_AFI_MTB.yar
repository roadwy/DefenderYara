
rule Ransom_MSIL_Filecoder_AFI_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 14 07 08 9a 0d 02 7b 26 00 00 04 09 6f ?? ?? ?? 0a 08 17 58 0c 08 07 8e 69 32 e6 03 6f ?? ?? ?? 0a 0a 06 2c 20 06 13 04 16 0c 2b 12 11 04 08 9a 13 05 02 11 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}