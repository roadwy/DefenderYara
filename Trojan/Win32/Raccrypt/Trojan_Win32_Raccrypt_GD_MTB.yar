
rule Trojan_Win32_Raccrypt_GD_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 f1 1a 2b c7 44 24 90 01 01 f9 0b 2b 23 89 4c 24 90 01 01 c7 44 24 90 01 01 d1 f0 0d 7b c7 44 24 90 01 01 68 17 ab 44 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 c7 05 90 01 04 ff ff ff ff 90 0a 32 00 c1 90 01 01 04 8b 90 02 0f c1 90 01 01 05 8d 90 02 0f 90 17 02 01 01 31 33 90 02 0f 90 17 02 01 01 31 33 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 84 32 36 23 01 00 88 04 31 81 c4 90 01 02 00 00 c3 90 00 } //10
		$a_02_1 = {c1 ea 05 03 d5 c7 05 90 01 04 b4 02 d7 cb c7 05 90 01 04 ff ff ff ff 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 74 24 90 01 01 8d 44 24 90 01 01 e8 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Raccrypt_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 90 0a 32 00 c1 90 01 01 04 03 90 02 0f c1 90 01 01 05 03 90 02 1e 90 17 02 01 01 31 33 90 02 14 c7 05 90 00 } //1
		$a_02_1 = {b4 21 e1 c5 90 0a 32 00 c1 90 01 01 05 03 90 02 0f c1 90 01 01 04 03 90 02 1e 90 17 02 01 01 31 33 90 02 14 c7 05 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GD_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 ff 35 90 02 14 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 6f 90 02 07 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 56 c6 05 90 01 04 72 c6 05 90 01 04 69 ff 15 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}