
rule Ransom_MSIL_BlackBit_ABB_MTB{
	meta:
		description = "Ransom:MSIL/BlackBit.ABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 05 00 00 0a 72 01 00 00 70 72 ec 02 00 70 1f 40 28 ?? ?? ?? 06 26 1f 23 28 ?? ?? ?? 0a 72 fe 02 00 70 28 ?? ?? ?? 0a 0a 06 28 ?? ?? ?? 0a 2c 1b 72 1a 03 00 70 72 2e 03 00 70 06 72 2e 03 00 70 } //2
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 66 00 69 00 6c 00 65 00 20 00 61 00 6e 00 64 00 20 00 61 00 6c 00 6c 00 20 00 6f 00 74 00 68 00 65 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 69 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 74 00 } //1 This file and all other files in your computer are encrypted by BlackBit
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}