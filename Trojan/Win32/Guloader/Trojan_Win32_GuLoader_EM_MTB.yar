
rule Trojan_Win32_GuLoader_EM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 00 72 00 66 00 74 00 73 00 76 00 75 00 6c 00 73 00 74 00 65 00 72 00 6e 00 65 00 } //1 Krftsvulsterne
		$a_01_1 = {4f 00 70 00 64 00 72 00 74 00 74 00 65 00 74 00 33 00 37 00 2e 00 56 00 65 00 64 00 } //1 Opdrttet37.Ved
		$a_01_2 = {43 00 68 00 69 00 6d 00 65 00 72 00 69 00 63 00 5c 00 52 00 61 00 62 00 69 00 61 00 74 00 65 00 73 00 } //1 Chimeric\Rabiates
		$a_01_3 = {6d 00 69 00 6e 00 69 00 64 00 75 00 6d 00 70 00 2d 00 61 00 6e 00 61 00 6c 00 79 00 7a 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 minidump-analyzer.exe
		$a_01_4 = {53 00 69 00 70 00 68 00 6f 00 6e 00 6f 00 73 00 74 00 6f 00 6d 00 61 00 74 00 6f 00 75 00 73 00 5c 00 48 00 6f 00 72 00 6e 00 65 00 64 00 64 00 65 00 76 00 69 00 6c 00 2e 00 42 00 69 00 6c 00 } //1 Siphonostomatous\Horneddevil.Bil
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_EM_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 e3 de d1 00 00 5b 81 ea 19 f5 00 00 41 35 82 18 00 00 43 81 f9 c2 b4 00 00 74 14 48 f7 d2 81 ea 13 54 01 00 b9 f8 7e 01 00 81 e2 10 03 00 00 05 c9 0d } //5
		$a_01_1 = {8b 47 3c 33 f6 8b 44 38 78 03 c7 8b 48 24 8b 50 20 03 cf 89 4d f8 03 d7 8b 48 1c 03 cf 89 55 fc 89 4d f4 8b 48 18 89 4d 08 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}