
rule Ransom_MSIL_BlackBit_NIT_MTB{
	meta:
		description = "Ransom:MSIL/BlackBit.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 05 00 00 0a 72 01 00 00 70 72 d0 02 00 70 1f 40 28 ?? 00 00 06 26 1f 23 28 ?? 00 00 0a 72 e2 02 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 2c 1b 72 fe 02 00 70 72 12 03 00 70 06 72 12 03 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 2a } //2
		$a_00_1 = {69 00 6e 00 66 00 6f 00 2e 00 42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 74 00 } //1 info.BlackBit
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}