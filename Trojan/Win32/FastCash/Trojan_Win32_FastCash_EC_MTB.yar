
rule Trojan_Win32_FastCash_EC_MTB{
	meta:
		description = "Trojan:Win32/FastCash.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 4d 79 46 63 2e 70 64 62 } //5 Win32\Release\MyFc.pdb
		$a_81_1 = {5c 78 36 34 5c 44 65 62 75 67 5c 4d 79 46 63 2e 70 64 62 } //5 \x64\Debug\MyFc.pdb
		$a_81_2 = {47 58 43 52 37 32 39 39 49 39 4d 4f 57 53 39 37 } //1 GXCR7299I9MOWS97
		$a_81_3 = {57 37 53 4c 46 53 47 34 4f 50 42 4a 4e 41 41 38 } //1 W7SLFSG4OPBJNAA8
		$a_81_4 = {74 6d 70 5c 69 6e 66 6f 2e 64 61 74 } //1 tmp\info.dat
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=8
 
}