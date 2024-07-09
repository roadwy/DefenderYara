
rule Trojan_Win64_CryptInject_MA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b c0 45 03 c7 99 f7 f9 48 63 c2 42 8a 04 10 41 30 01 4d 03 cf 41 83 f8 02 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CryptInject_MA_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f af 4f 4c 41 8b d1 c1 ea 08 88 14 01 ff 05 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 48 40 03 4f 30 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CryptInject_MA_MTB_3{
	meta:
		description = "Trojan:Win64/CryptInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {f9 dc b6 31 84 eb ea d0 15 ed 97 37 01 f4 26 d1 2c a3 32 a8 bd aa c7 b7 29 63 de c6 2c f3 1a 0f 4d 1a 17 77 e1 5b 37 43 bb ec dd fa 5a fa fb 75 } //5
		$a_01_1 = {12 30 cc cc 78 80 ad dd fe b7 f2 fb 2a c1 51 36 e0 4d 19 36 d2 47 32 48 b9 a9 c3 28 77 4b a3 6a 80 ad dd fe bf b2 f8 78 9f 1a aa fc 82 ad dd fe } //5
		$a_01_2 = {f0 00 27 00 0b 02 02 18 00 32 00 00 00 2a 00 00 00 0c 00 00 75 c7 06 00 00 10 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}