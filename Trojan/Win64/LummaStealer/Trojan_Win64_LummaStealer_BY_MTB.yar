
rule Trojan_Win64_LummaStealer_BY_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c8 f7 d2 09 c2 69 c2 95 e9 d1 5b 69 4c 24 64 95 e9 d1 5b 41 89 cd 41 31 c5 44 21 e9 41 21 c5 89 c8 44 21 e8 41 31 cd 41 09 c5 8b 44 24 68 83 c0 01 89 44 24 24 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}