
rule Trojan_Win64_IcedId_SIBC_MTB{
	meta:
		description = "Trojan:Win64/IcedId.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {48 85 c9 74 90 01 01 44 8a 11 45 84 d2 74 90 01 01 ff ca 31 c0 41 b9 90 01 04 45 8d 5a 90 01 01 41 0f b6 fa 41 80 c2 90 01 01 41 0f b6 f2 45 84 c0 0f 44 f7 41 80 fb 90 01 01 0f 43 f7 89 c7 c1 c7 90 01 01 40 0f be c6 31 f8 44 39 ca 72 90 01 01 46 8a 14 09 49 ff c1 45 84 d2 75 90 01 01 35 90 01 04 eb 90 00 } //1
		$a_02_1 = {48 89 46 ff c7 46 90 01 05 66 c7 46 90 01 03 b8 90 01 04 80 74 04 90 01 02 48 ff c0 48 83 f8 90 01 01 75 90 01 01 c6 44 24 90 01 01 00 31 c9 ba 90 01 04 41 b8 90 01 04 e8 90 01 04 48 89 f1 ff d0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}