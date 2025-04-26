
rule Trojan_Win64_Zusy_RG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c7 48 89 5c 24 30 c7 44 24 28 e8 03 00 00 c7 44 24 20 02 00 00 00 48 89 c1 ba 0a 04 00 00 45 31 c0 45 31 c9 ff 15 73 c2 45 00 48 81 7d e0 0a 04 00 00 75 2b c7 85 20 02 00 00 00 00 00 00 48 8d 95 20 02 00 00 48 89 f9 ff 15 d7 c1 45 00 } //1
		$a_01_1 = {45 3a 5c 50 72 6f 6a 65 63 74 73 5c 6d 75 6c 74 69 6c 6f 61 64 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 69 6e 6a 2e 70 64 62 } //1 E:\Projects\multiloader\bin\Release\inj.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}