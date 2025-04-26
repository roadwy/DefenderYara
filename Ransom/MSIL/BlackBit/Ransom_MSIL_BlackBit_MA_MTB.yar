
rule Ransom_MSIL_BlackBit_MA_MTB{
	meta:
		description = "Ransom:MSIL/BlackBit.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 05 00 00 0a 72 01 00 00 70 72 ?? 02 00 70 1f 40 28 01 00 00 06 26 1f 23 28 06 00 00 0a 72 ?? ?? 00 70 28 07 00 00 0a 0a 06 28 08 00 00 0a 2c 1b 72 ?? 03 00 70 72 ?? 03 00 70 06 72 ?? 03 00 70 28 09 00 00 0a 28 0a 00 00 0a 26 2a } //5
		$a_01_1 = {69 00 6e 00 66 00 6f 00 2e 00 42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 74 00 } //2 info.BlackBit
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}