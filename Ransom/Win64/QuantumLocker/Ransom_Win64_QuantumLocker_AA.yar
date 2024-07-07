
rule Ransom_Win64_QuantumLocker_AA{
	meta:
		description = "Ransom:Win64/QuantumLocker.AA,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {0f b7 44 24 20 66 ff c0 66 89 44 24 20 0f b7 44 24 20 0f b7 4c 24 24 3b c1 7d 31 8b 4c 24 28 e8 90 01 04 89 44 24 28 0f b7 44 24 20 48 8b 4c 24 40 0f b6 04 01 0f b6 4c 24 28 33 c1 0f b7 4c 24 20 48 8b 54 24 48 88 04 0a eb b4 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}