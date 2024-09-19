
rule Trojan_Win64_Rozena_MBXR_MTB{
	meta:
		description = "Trojan:Win64/Rozena.MBXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 35 46 65 6a 4e 5a 63 39 73 41 4c 47 32 77 2d 73 6d 4c 36 2d 2f 53 4c 4c 55 6e 79 76 37 78 54 55 6d 31 75 73 59 2d 6a 68 4c 2f 62 43 45 4a 4a 39 51 77 78 51 5f 42 4e 52 43 6e 45 5a 32 78 2f 2d 48 6c 61 52 43 52 44 35 4a 78 } //1 Go build ID: "5FejNZc9sALG2w-smL6-/SLLUnyv7xTUm1usY-jhL/bCEJJ9QwxQ_BNRCnEZ2x/-HlaRCRD5Jx
		$a_01_1 = {54 77 6a 69 77 71 39 64 6e 36 52 31 66 51 63 79 69 4b 2b 77 51 79 48 57 66 61 7a 2f 42 4a 42 2b 59 49 70 7a 55 2f 43 76 33 58 } //1 Twjiwq9dn6R1fQcyiK+wQyHWfaz/BJB+YIpzU/Cv3X
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}