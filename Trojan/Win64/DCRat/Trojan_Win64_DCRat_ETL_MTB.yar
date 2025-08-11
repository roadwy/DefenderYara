
rule Trojan_Win64_DCRat_ETL_MTB{
	meta:
		description = "Trojan:Win64/DCRat.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 a1 a0 a0 a0 41 f7 e0 c1 ea 05 0f be c2 6b c8 33 41 0f b6 c0 2a c1 04 32 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 10 7c d7 } //2
		$a_81_1 = {4c 6f 61 64 65 72 2e 70 64 62 } //1 Loader.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}