
rule Ransom_MSIL_BlockCrypt_PB_MTB{
	meta:
		description = "Ransom:MSIL/BlockCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 43 00 20 00 6e 00 65 00 74 00 20 00 76 00 69 00 65 00 77 00 } //1 /C net view
		$a_01_1 = {07 08 03 08 91 04 61 d2 9c 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d e9 } //2
		$a_03_2 = {07 08 07 08 93 ?? 61 d1 9d 06 07 08 93 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 00 08 17 58 0c 08 07 8e 69 fe ?? 0d 09 2d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=5
 
}