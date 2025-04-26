
rule Ransom_Win64_Proton_MA_MTB{
	meta:
		description = "Ransom:Win64/Proton.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {dd fe 7f fb 48 89 5c 24 08 08 7c 24 10 55 48 8d 6c 24 a9 48 81 ec 90 00 00 c6 45 e7 7d 9a cd f6 06 e8 79 0e e9 71 ea 72 eb ec 28 fe 7b 9e a7 1e } //2
		$a_01_1 = {6b c8 1a b8 09 04 02 81 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 bf 43 ec ff 1f 03 d0 6b c2 7f 2b c8 83 c1 7f 35 42 88 82 49 ff c0 dc df fe ff 49 83 f8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}