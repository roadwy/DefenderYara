
rule Trojan_Win64_Emotetcrypt_JV_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 b8 5f 43 79 0d e5 35 94 d7 41 83 c2 01 49 f7 e1 48 c1 ea 04 48 6b d2 13 4c 2b ca 4c 2b ce 4d 2b cc 4c 2b cf 4d 2b c8 4c 2b cd 4d 03 cd 41 8a 04 09 4d 63 ca 41 32 03 49 83 c3 01 88 03 48 83 c3 01 4d 3b ce 72 } //1
		$a_03_1 = {48 8b 44 24 48 0f b6 04 08 03 44 24 30 41 8b d0 33 d0 8b 0d 90 01 04 8b 04 24 2b c1 2b 05 90 01 04 2b 05 90 01 04 48 63 c8 48 8b 44 24 38 88 14 08 e9 90 00 } //1
		$a_01_2 = {44 32 04 01 49 8d 45 01 49 8d 49 01 49 0f af ce 49 0f af c5 48 03 c0 48 2b d0 48 83 c1 01 49 0f af cb 49 0f af d7 49 03 ca 48 8d 04 16 48 03 cb 48 83 c6 01 48 8d 0c 48 48 8b 44 24 78 48 89 b4 24 80 00 00 00 44 88 04 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}