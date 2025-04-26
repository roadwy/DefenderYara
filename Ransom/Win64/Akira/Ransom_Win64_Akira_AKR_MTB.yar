
rule Ransom_Win64_Akira_AKR_MTB{
	meta:
		description = "Ransom:Win64/Akira.AKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8b c3 4d 8b d5 41 83 e5 3f 49 c1 fa 06 4e 8d 1c ed 00 00 00 00 4d 03 dd 41 8a 04 38 41 ff c1 4b 8b 8c d7 10 55 0f 00 49 03 c8 49 ff c0 42 88 44 d9 3e 49 63 c1 48 3b c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}