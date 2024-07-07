
rule Ransom_Win64_MagniberPacker_AO_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 ff c6 e9 90 0a 05 00 48 ff c6 90 13 48 ff c7 90 13 48 ff c2 90 13 48 81 fa 90 01 04 90 13 90 13 8a ae 90 01 04 90 13 32 ae 90 01 04 90 13 32 e8 90 13 8a c5 90 13 88 2f 90 13 48 ff c6 90 00 } //1
		$a_03_1 = {48 ff c6 eb 90 0a 05 00 48 ff c6 90 13 48 ff c7 90 13 48 ff c2 90 13 48 81 fa 90 01 04 90 13 90 13 8a ae 90 01 04 90 13 32 ae 90 01 04 90 13 32 e8 90 13 8a c5 90 13 88 2f 90 13 48 ff c6 90 00 } //1
		$a_03_2 = {48 ff c6 e9 90 0a 05 00 48 ff c6 90 13 48 ff c7 90 13 48 ff c2 90 13 48 81 fa 90 01 04 90 13 90 13 8a ae 90 01 04 90 13 32 ae 90 01 04 90 13 32 ec 90 13 8a e5 90 13 88 2f 90 13 48 ff c6 90 00 } //1
		$a_03_3 = {48 ff c6 eb 90 0a 05 00 48 ff c6 90 13 48 ff c7 90 13 48 ff c2 90 13 48 81 fa 90 01 04 90 13 90 13 8a ae 90 01 04 90 13 32 ae 90 01 04 90 13 32 ec 90 13 8a e5 90 13 88 2f 90 13 48 ff c6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}