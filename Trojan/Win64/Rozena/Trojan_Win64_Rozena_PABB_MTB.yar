
rule Trojan_Win64_Rozena_PABB_MTB{
	meta:
		description = "Trojan:Win64/Rozena.PABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 48 69 d2 d3 4d 62 10 48 c1 ea 20 c1 fa 06 89 c1 c1 f9 1f 29 ca 69 ca e8 03 00 00 29 c8 89 c2 66 0f ef f6 f2 0f 2a f2 e8 90 01 03 00 48 63 d0 48 69 d2 eb a0 0e ea 48 c1 ea 20 01 c2 c1 fa 06 89 c1 c1 f9 1f 29 ca 6b ca 46 29 c8 89 c2 66 0f ef c9 f2 0f 2a ca 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}