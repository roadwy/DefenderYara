
rule Ransom_Linux_Lockbit_CD_MTB{
	meta:
		description = "Ransom:Linux/Lockbit.CD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 46 b9 6b fe f7 c6 ec df f8 a0 c3 d7 e9 0e 01 dc e9 00 23 10 eb 02 0b 41 eb 03 0e 5a 46 73 46 cc e9 00 23 b8 f1 00 0f 02 d0 40 46 fe f7 16 eb } //1
		$a_01_1 = {74 49 07 f5 dc 6a d1 e9 02 23 54 1c 43 f1 00 05 d1 e9 04 23 c1 e9 02 45 da e9 00 45 a4 18 45 eb 03 09 22 46 4b 46 c1 e9 04 23 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}