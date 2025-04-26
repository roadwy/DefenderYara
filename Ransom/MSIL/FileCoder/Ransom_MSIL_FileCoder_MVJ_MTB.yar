
rule Ransom_MSIL_FileCoder_MVJ_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 78 04 00 70 73 b0 00 00 0a 0b 07 17 6f b1 00 00 0a 00 07 72 88 04 00 70 6f b2 00 00 0a 00 07 72 c2 04 00 70 6f b2 00 00 0a 00 07 28 b3 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}