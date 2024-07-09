
rule Ransom_Win32_Hive_MK_MTB{
	meta:
		description = "Ransom:Win32/Hive.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f2 89 4c 24 ?? c1 e2 ?? 31 f2 89 d6 c1 ee ?? 89 34 24 89 ce c1 e9 ?? 31 f1 33 ?? 24 89 ce 31 d6 8b 54 24 0c 89 50 ?? 89 70 ?? 01 d6 b2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}