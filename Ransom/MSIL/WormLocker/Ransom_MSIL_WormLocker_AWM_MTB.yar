
rule Ransom_MSIL_WormLocker_AWM_MTB{
	meta:
		description = "Ransom:MSIL/WormLocker.AWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 22 00 11 04 11 09 9a 28 ?? 00 00 0a 00 11 05 11 04 11 09 9a 11 06 6f ?? 00 00 06 00 00 11 09 17 58 13 09 11 09 11 04 8e 69 } //2
		$a_01_1 = {57 6f 72 6d 5f 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 57 6f 72 6d 5f 4c 6f 63 6b 65 72 2e 70 64 62 } //1 Worm_Locker\obj\Debug\Worm_Locker.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}