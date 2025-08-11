
rule Ransom_MSIL_FileCoder_MJ_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 03 00 00 04 7e 02 00 00 04 07 28 07 00 00 06 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}