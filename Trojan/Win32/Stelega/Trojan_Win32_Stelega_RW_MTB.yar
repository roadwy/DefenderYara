
rule Trojan_Win32_Stelega_RW_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 09 ff e8 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 29 f8 31 0b 01 f8 09 c7 43 81 c0 12 6c ea ad } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Stelega_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Stelega.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 ee f0 85 07 86 e8 ?? ?? ?? ?? 42 31 19 89 d2 01 d6 41 09 d2 39 c1 75 } //1
		$a_03_1 = {bb b2 c9 4e 00 40 e8 ?? ?? ?? ?? b8 14 14 3e 71 31 1e 21 c0 49 81 c6 01 00 00 00 21 c1 39 fe 75 df } //1
		$a_00_2 = {81 ef 47 82 38 7e 31 02 09 cb 89 cb 42 49 f7 d1 81 c6 01 00 00 00 } //1
		$a_00_3 = {81 e9 bc 68 1d 4f 01 d9 31 30 b9 a5 95 dc d9 bf c8 c8 fe 14 29 df 40 01 cf 81 c1 af 07 21 4c } //1
		$a_00_4 = {89 ca 01 d2 81 c2 01 00 00 00 31 3b 81 ea 01 00 00 00 81 e9 56 51 f4 b4 01 f6 43 21 f2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=1
 
}
rule Trojan_Win32_Stelega_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Stelega.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 c0 43 81 c0 ?? ?? ?? ?? 31 0e 48 f7 d3 81 c3 71 f6 8f 39 81 c6 02 00 00 00 89 d8 21 db bb ?? ?? ?? ?? 39 fe 7c } //1
		$a_03_1 = {29 f0 be a9 d1 a8 fd 31 11 21 f0 81 c6 ?? ?? ?? ?? 09 f6 81 c1 02 00 00 00 81 e8 ?? ?? ?? ?? 39 f9 7c } //1
		$a_03_2 = {29 f7 81 c7 ?? ?? ?? ?? be 16 2a 95 05 89 f7 31 02 81 c6 ?? ?? ?? ?? 4f 89 f7 81 c2 02 00 00 00 29 f6 be ?? ?? ?? ?? 39 ca 7c } //1
		$a_03_3 = {29 fe 81 c7 1b 61 0d ee 01 f7 31 11 f7 d6 81 c1 02 00 00 00 29 ff 39 c1 7c ?? 29 ff 4e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Stelega_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Stelega.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 0a 00 00 "
		
	strings :
		$a_03_0 = {21 c9 89 c9 e8 ?? ?? ?? ?? 21 c1 21 c8 31 3e 09 c0 81 c6 02 00 00 00 b9 e8 66 ad a6 81 e9 5c 3e 9d 49 81 c0 37 07 49 e7 39 d6 7c } //1
		$a_03_1 = {be a2 72 84 00 81 e8 01 00 00 00 40 e8 ?? ?? ?? ?? 48 01 c7 31 33 48 57 8b 04 24 83 c4 04 } //1
		$a_03_2 = {01 fe 4f e8 ?? ?? ?? ?? 09 f6 bf a6 bd bd 7a 01 f6 31 03 09 f7 bf ed 80 34 ef 01 f7 81 c3 } //1
		$a_03_3 = {83 c4 04 81 e9 9c 70 99 09 e8 ?? ?? ?? ?? 29 f9 01 f9 31 18 4f 21 f9 81 c0 02 00 00 00 } //1
		$a_03_4 = {be 83 07 9c 38 e8 ?? ?? ?? ?? 83 ec 04 c7 04 24 c0 a0 7b 3e 8b 34 24 83 c4 04 31 3b 81 ee 01 00 00 00 43 } //1
		$a_03_5 = {81 ee 3a 1b 3e 24 e8 ?? ?? ?? ?? 81 c6 57 9a c7 c2 89 f2 31 1f 21 f2 29 f2 81 c7 02 00 00 00 81 ea 80 31 5b d8 39 } //1
		$a_00_6 = {bb 3d c6 cc c7 31 06 68 1d c5 0a 27 8b 14 24 83 c4 04 01 d3 46 01 d2 01 d3 } //1
		$a_03_7 = {bf a8 03 c4 05 01 d2 e8 ?? ?? ?? ?? 4a 21 d7 31 18 bf 60 92 79 7e 40 09 ff 01 d2 } //1
		$a_03_8 = {bb dc 87 5d 00 29 ff e8 ?? ?? ?? ?? 81 e8 01 00 00 00 31 1a 89 c7 81 e8 36 cb b2 f2 29 f8 81 c2 02 00 00 00 } //1
		$a_03_9 = {81 c7 8f b0 92 b7 89 cf 21 f9 e8 ?? ?? ?? ?? 81 c1 4c cd 46 cf 31 06 81 e9 8e c3 40 98 46 81 c7 01 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_00_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1) >=1
 
}