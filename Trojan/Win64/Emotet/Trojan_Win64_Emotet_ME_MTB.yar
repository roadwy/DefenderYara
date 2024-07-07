
rule Trojan_Win64_Emotet_ME_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c8 48 2b f0 b8 90 01 04 41 f7 e8 c1 fa 03 8b c2 c1 e8 1f 03 d0 49 63 c0 41 83 c0 01 48 63 ca 48 6b c9 19 48 03 c8 48 8d 05 90 01 04 8a 04 01 42 32 04 0e 41 88 01 49 83 c1 01 44 3b c5 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win64_Emotet_ME_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 63 4c 24 30 48 8b 44 24 50 44 0f b6 04 08 8b 44 24 30 99 b9 90 01 04 f7 f9 48 63 ca 48 8b 44 24 20 0f b6 04 08 41 8b d0 33 d0 48 63 4c 24 30 48 8b 44 24 28 88 14 08 eb 90 00 } //10
		$a_03_1 = {41 f7 e8 c1 fa 03 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 6b d2 1b 2b c2 48 63 c8 48 8d 05 90 01 04 8a 04 01 42 32 04 0e 41 88 01 49 ff c1 44 3b c5 72 90 00 } //10
		$a_03_2 = {41 f7 e8 41 03 d0 c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 6b d2 1e 2b c2 48 63 c8 48 8d 05 90 01 04 8a 04 01 42 32 04 0e 41 88 01 49 ff c1 44 3b c5 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=10
 
}