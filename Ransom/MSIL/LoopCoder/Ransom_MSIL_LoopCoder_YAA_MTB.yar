
rule Ransom_MSIL_LoopCoder_YAA_MTB{
	meta:
		description = "Ransom:MSIL/LoopCoder.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 72 15 00 00 70 1b 6f 13 00 00 0a 2d 1e 07 72 1d 00 00 70 1b 6f 13 00 00 0a 2d 10 } //1
		$a_01_1 = {12 09 28 21 00 00 0a 13 0a 72 ff 00 00 70 } //1
		$a_01_2 = {43 68 61 6e 67 65 45 78 74 65 6e 73 69 6f 6e } //1 ChangeExtension
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}