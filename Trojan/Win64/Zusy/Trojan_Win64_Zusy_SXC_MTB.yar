
rule Trojan_Win64_Zusy_SXC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b9 00 00 00 00 49 89 d0 48 89 c2 b9 00 00 00 00 48 8b 05 29 8c 01 00 ff d0 b9 f4 01 00 00 48 8b 05 db 89 01 00 ff d0 48 8d 85 90 00 48 89 c1 48 8b 05 28 89 01 00 ff d0 } //3
		$a_01_1 = {48 8d 85 c0 01 00 00 41 b8 00 00 00 00 48 89 c1 48 8b 05 46 8e 01 00 ff d0 48 8d 45 b0 ba 06 00 00 00 48 89 c1 48 8b 05 f1 8e 01 00 ff d0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}