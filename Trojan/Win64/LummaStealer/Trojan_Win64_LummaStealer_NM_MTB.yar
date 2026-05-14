
rule Trojan_Win64_LummaStealer_NM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 48 89 4c 24 30 89 4c 24 38 49 ba 70 d1 54 54 6f 07 a8 e8 48 21 4c 24 20 44 8d 49 0c 8d 51 01 48 8b c8 48 8b c7 4c 8d 44 24 30 ff 15 ff 73 03 00 } //3
		$a_01_1 = {85 c0 74 08 8a 44 24 38 24 01 eb 06 32 c0 eb 02 b0 01 48 8b 4c 24 40 48 33 cc e8 c8 c2 fa ff 48 8b 5c 24 60 48 83 c4 50 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win64_LummaStealer_NM_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 89 14 24 48 8d 91 98 02 00 00 48 89 54 24 08 e8 4d 2c 03 00 0f b6 44 24 1f 84 c0 74 26 48 8b 44 24 20 48 c7 80 d0 02 00 00 00 00 00 00 48 8b 80 b0 02 00 00 48 89 44 24 40 48 8b 6c 24 28 } //2
		$a_01_1 = {4c 01 cf 49 89 c2 48 29 d0 48 c1 f8 3f 4c 21 d0 4c 8d 1c 18 4c 39 df 0f 84 63 ff ff ff 4c 89 54 24 20 4c 89 44 24 18 48 89 3c 24 4c 89 5c 24 08 4c 89 44 24 10 e8 58 ef 02 00 48 8b 54 24 48 48 8b 5c 24 38 48 8b 74 24 40 4c 8b 44 24 18 } //1
		$a_01_2 = {47 6f 20 62 75 69 6c 64 } //1 Go build
		$a_01_3 = {74 72 79 6e 6f 77 2e 63 6f 6d 30 } //1 trynow.com0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}