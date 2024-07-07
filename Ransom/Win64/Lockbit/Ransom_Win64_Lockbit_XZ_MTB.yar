
rule Ransom_Win64_Lockbit_XZ_MTB{
	meta:
		description = "Ransom:Win64/Lockbit.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 be 02 00 00 00 4c 8b 40 18 b8 56 55 55 55 c7 45 10 b2 88 1d 00 8b 4d 10 f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}