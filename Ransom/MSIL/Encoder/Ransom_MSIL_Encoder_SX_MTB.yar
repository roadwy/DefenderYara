
rule Ransom_MSIL_Encoder_SX_MTB{
	meta:
		description = "Ransom:MSIL/Encoder.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 8f 0a 00 00 01 25 71 0a 00 00 01 08 11 05 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a d2 61 d2 81 0a 00 00 01 11 05 17 58 13 05 11 05 11 04 8e 69 32 cc 09 72 ?? ?? 00 70 28 ?? 00 00 0a 11 04 28 ?? 00 00 0a 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}