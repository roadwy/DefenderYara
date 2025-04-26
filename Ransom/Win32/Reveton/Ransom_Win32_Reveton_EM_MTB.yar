
rule Ransom_Win32_Reveton_EM_MTB{
	meta:
		description = "Ransom:Win32/Reveton.EM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 55 e0 8a 1e 8b 75 e8 8d 7e 01 89 7d e8 88 1e 8b 75 e4 01 ce 89 55 e0 89 75 e4 8b 55 e4 f7 5d c8 } //10
		$a_01_1 = {2b 85 50 ff ff ff 8b 8d 58 ff ff ff 01 f1 20 9d 3b ff ff ff 89 8d 58 ff ff ff 31 c9 2b 8d 40 ff ff ff 89 85 50 ff ff ff 89 8d 40 ff ff ff 8b 85 58 ff ff ff } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}