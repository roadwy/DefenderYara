
rule Ransom_MSIL_FileCoder_YAR_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.YAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 11 07 ?? ?? ?? ?? ?? 08 11 08 02 11 08 91 07 07 11 06 91 07 11 07 91 58 20 00 01 00 00 5d 91 61 d2 9c 11 08 17 58 13 08 11 08 02 8e 69 32 b3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}