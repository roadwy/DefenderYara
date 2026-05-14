
rule Trojan_Win64_LummaStealer_PGLN_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 7c 24 10 8b 7c 24 14 01 df 8b 5c 24 14 31 fa c1 c2 10 41 01 d0 44 31 c3 c1 c3 0c 01 df 31 fa c1 c2 08 41 01 d0 44 31 c3 c1 c3 07 83 6c 24 08 01 } //5
		$a_01_1 = {f3 0f 6f 03 66 0f ef 00 48 83 c3 10 48 83 c0 10 0f 11 43 f0 4c 39 fb 75 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}