
rule Ransom_Win32_BastaLoader_BE_MTB{
	meta:
		description = "Ransom:Win32/BastaLoader.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {1b c5 30 07 82 fe 90 01 01 ef 03 b7 90 01 04 00 40 90 01 01 01 16 90 00 } //1
		$a_03_1 = {f8 01 2a bb 90 01 04 94 2b 92 90 01 04 fc 2a 7f 90 01 01 34 90 01 01 20 02 d2 05 90 01 04 21 ac fb 90 01 04 01 7c 71 90 01 01 1e 8d 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}