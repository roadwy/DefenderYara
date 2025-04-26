
rule Trojan_Win64_PrivateLoader_CZ_MTB{
	meta:
		description = "Trojan:Win64/PrivateLoader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 0f be 14 18 49 ff c0 41 69 c9 9f f2 10 00 03 d1 81 e2 ff ff ff 00 44 03 ca 4c 3b c0 72 } //1
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 65 70 20 42 79 70 61 73 73 20 2d 63 20 } //1 powershell -NoProfile -ep Bypass -c 
		$a_81_2 = {29 72 65 74 75 72 6e 20 5b 53 79 73 74 65 6d 2e 4c 69 6e 71 2e 45 6e 75 6d 65 72 61 62 6c 65 5d 3a 3a 52 65 76 65 72 73 65 28 24 } //1 )return [System.Linq.Enumerable]::Reverse($
		$a_81_3 = {28 5c 22 70 75 74 72 61 74 53 5c 22 29 3b 24 } //1 (\"putratS\");$
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}