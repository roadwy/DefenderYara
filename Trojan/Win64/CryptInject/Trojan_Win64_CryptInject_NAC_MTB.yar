
rule Trojan_Win64_CryptInject_NAC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {45 3a 5c 43 6f 64 65 5c 54 32 48 5c 43 75 73 74 6f 6d 42 75 69 6c 64 73 5c 43 72 65 61 74 65 43 75 73 74 6f 6d 42 75 69 6c 64 73 5c 52 65 6c 65 61 73 65 5c 42 6f 6f 74 53 74 72 61 70 70 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 42 6f 6f 74 53 74 72 61 70 70 65 72 2e 70 64 62 } //2 E:\Code\T2H\CustomBuilds\CreateCustomBuilds\Release\BootStrapper\x64\Release\BootStrapper.pdb
		$a_01_1 = {8b 45 18 48 8d 4d f0 48 c1 e0 20 48 33 45 18 48 33 45 f0 48 33 c1 } //1
		$a_01_2 = {45 0b d0 89 45 f0 41 81 f1 47 65 6e 75 89 5d f4 45 0b d1 89 4d f8 8b f9 89 55 fc } //1
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}