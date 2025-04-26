
rule Trojan_Win64_DCRat_F_MTB{
	meta:
		description = "Trojan:Win64/DCRat.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 13 48 83 ?? 01 49 0f be 4c 02 01 4d 0f be 14 02 41 0f be 0c ?? 47 0f be 14 ?? c1 f9 04 41 c1 e2 02 83 e1 03 44 09 d1 4c 8b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}