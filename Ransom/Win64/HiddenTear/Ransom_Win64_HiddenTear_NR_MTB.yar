
rule Ransom_Win64_HiddenTear_NR_MTB{
	meta:
		description = "Ransom:Win64/HiddenTear.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 8c 24 88 00 00 00 ba 10 00 00 00 89 c5 0f b6 f0 0f b6 fc c1 e8 18 c1 ed 10 89 74 24 30 41 89 c1 44 0f b6 c5 89 7c 24 28 bd 00 02 00 00 44 89 44 24 20 } //2
		$a_01_1 = {41 89 c4 89 c2 e9 85 00 00 00 80 fa 18 0f 85 81 00 00 00 48 8b 7c 24 60 49 8d 74 0e 02 0f b6 cb 41 bf 01 00 00 00 f3 a4 48 8b 4c 24 60 } //1
		$a_01_2 = {43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 43 26 43 20 73 65 72 76 65 72 } //1 Connected to C&C server
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}