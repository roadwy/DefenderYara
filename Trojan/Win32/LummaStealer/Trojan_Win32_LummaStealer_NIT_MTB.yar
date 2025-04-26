
rule Trojan_Win32_LummaStealer_NIT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 75 00 8d 4e bf 66 83 f9 1a 73 03 83 ce 20 0f b7 0b 8d 41 bf 66 83 f8 1a 73 03 83 c9 20 66 85 f6 74 0b 83 c5 02 83 c3 02 66 39 ce 74 d1 } //2
		$a_01_1 = {21 cf 09 f7 21 d7 09 c2 31 fa 80 c2 da 88 54 04 ef 40 49 83 f8 27 75 d7 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_LummaStealer_NIT_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 d9 80 c1 a8 32 0c 18 80 c1 b0 88 0c 18 43 83 fb 04 75 ec ff 25 ?? ?? ?? ?? 31 c9 39 10 0f 95 c1 31 c0 ff 24 8d ?? ?? ?? ?? 89 7d e8 8b 45 08 8b 48 3c 89 4d ec 8b 04 08 89 45 f0 89 f1 } //2
		$a_01_1 = {89 ca 80 c2 6d 32 14 08 80 c2 26 88 14 08 41 83 f9 14 75 ec } //1
		$a_01_2 = {0f b6 54 0e 94 89 d3 21 cb 00 db 28 da 0f b6 d2 01 ca 80 c2 28 88 54 0e 94 41 83 f9 70 75 e1 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_Win32_LummaStealer_NIT_MTB_3{
	meta:
		description = "Trojan:Win32/LummaStealer.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 69 52 4e 67 72 77 38 33 36 52 79 45 0d 0a 4b 67 49 38 57 43 73 4b 62 41 30 5a 47 65 54 68 63 31 47 43 37 57 4e 33 6b 59 64 57 52 58 74 55 32 53 2b 61 75 4a 48 4d 70 41 31 37 44 4a 4d 79 4e 6d 73 6e 37 44 41 43 32 51 4b 42 67 44 62 33 0d 0a 6b 65 63 71 56 52 6c 78 6f 6e 41 71 50 55 46 5a 33 43 36 50 37 6b 53 58 4e 37 43 } //2
		$a_01_1 = {41 66 53 64 4e 4d 36 2f 34 36 4f 62 49 4a 4a 6d 57 48 48 76 70 56 4a } //2 AfSdNM6/46ObIJJmWHHvpVJ
		$a_01_2 = {66 bb 19 5a 66 83 c3 34 66 39 18 75 12 0f b7 50 3c 03 d0 bb e9 44 00 00 83 c3 67 39 1a 74 07 2d 00 10 00 00 eb da } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}