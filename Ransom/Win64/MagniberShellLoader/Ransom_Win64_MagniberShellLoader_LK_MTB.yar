
rule Ransom_Win64_MagniberShellLoader_LK_MTB{
	meta:
		description = "Ransom:Win64/MagniberShellLoader.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 fb 04 75 05 40 88 39 eb 05 0f b6 02 88 01 ff c3 48 ff c1 48 ff c2 83 fb 0b 72 e4 } //1
		$a_01_1 = {66 c7 40 f0 0f 05 c6 40 f2 c3 48 c7 40 20 0b 00 00 00 c7 40 d8 00 10 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}