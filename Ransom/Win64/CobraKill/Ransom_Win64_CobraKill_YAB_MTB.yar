
rule Ransom_Win64_CobraKill_YAB_MTB{
	meta:
		description = "Ransom:Win64/CobraKill.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 0f be 7d 00 48 63 84 24 88 00 00 00 49 31 c7 4c 89 f8 50 48 8b ac 24 a8 00 00 00 58 88 45 00 } //1
		$a_01_1 = {f7 80 14 e8 2e ad 6b f9 73 9e e9 21 43 c5 d9 e7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}