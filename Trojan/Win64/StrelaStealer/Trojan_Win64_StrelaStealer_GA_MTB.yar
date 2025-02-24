
rule Trojan_Win64_StrelaStealer_GA_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 0f b6 6c 38 04 43 0f b6 8c 3b 04 04 00 00 } //1
		$a_01_1 = {89 cb f6 d3 08 da 80 e3 ec 80 e1 13 08 d9 30 c1 f6 d2 08 ca 44 89 e0 f6 d0 20 d0 f6 d2 44 20 e2 08 c2 43 88 94 3b 04 04 00 00 } //1
		$a_01_2 = {c7 44 24 30 07 04 0a 04 41 b8 04 01 00 00 c7 44 24 34 0a 0c 03 04 48 8d 8c 24 50 01 00 00 c7 44 24 38 2d 04 10 04 c7 44 24 3c 15 04 22 04 } //1
		$a_01_3 = {44 8b c7 4c 8d 1d 50 78 01 00 44 8b d0 4c 8b cb 66 66 0f 1f 84 00 00 00 00 00 33 d2 4d 8d 49 01 41 8b c0 41 ff c0 41 f7 f2 42 0f b6 0c 1a 41 30 49 ff 44 3b c6 72 e3 } //1
		$a_01_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}