
rule Trojan_Win64_CryptInject_YAA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 33 c1 44 69 c8 90 01 04 66 41 0f be c3 41 8b c1 45 3a c4 f9 c1 e8 0f 44 3b f4 f8 44 33 c8 8a 01 f6 c5 3a 84 c0 90 00 } //1
		$a_03_1 = {83 e0 03 f9 8a 44 05 90 01 01 f8 66 41 3b c6 4d 85 d4 30 02 49 03 d4 41 f6 c3 4f 85 f2 4d 2b f4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}