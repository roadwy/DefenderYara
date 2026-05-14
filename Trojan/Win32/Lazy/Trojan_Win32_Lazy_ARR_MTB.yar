
rule Trojan_Win32_Lazy_ARR_MTB{
	meta:
		description = "Trojan:Win32/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 74 69 6e 67 20 48 54 54 50 20 42 79 70 61 73 73 20 46 6c 6f 6f 64 20 6f 6e } //4 Starting HTTP Bypass Flood on
		$a_81_1 = {7b 22 71 75 65 72 79 22 3a 22 7b 20 5f 5f 73 63 68 65 6d 61 20 7b 20 74 79 70 65 73 20 7b 20 6e 61 6d 65 20 66 69 65 6c 64 73 20 7b 20 6e 61 6d 65 20 7d 20 7d 20 7d 20 7d 22 7d } //6 {"query":"{ __schema { types { name fields { name } } } }"}
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 73 65 6b 6b 6b 61 2f 74 61 68 61 2f 72 61 77 2f 6d 61 69 6e 2f 72 79 78 2e 74 78 74 } //10 https://bitbucket.org/sekkka/taha/raw/main/ryx.txt
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*6+(#a_01_2  & 1)*10) >=20
 
}