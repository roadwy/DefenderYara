
rule Trojan_Win64_CryptInject_AG_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6e 61 74 63 68 69 6e 67 20 74 68 72 65 61 64 73 20 69 6e 20 74 68 65 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 20 75 73 69 6e 67 20 76 75 6c 6e 65 72 61 62 6c 65 20 64 72 69 76 65 72 } //1 snatching threads in the target process using vulnerable driver
		$a_01_1 = {65 76 69 6c 2d 6d 68 79 70 72 6f 74 2d 63 6c 69 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 65 76 69 6c 2d 6d 68 79 70 72 6f 74 2d 63 6c 69 36 34 2e 70 64 62 } //1 evil-mhyprot-cli\x64\Release\evil-mhyprot-cli64.pdb
		$a_01_2 = {73 6e 61 74 63 68 69 6e 67 20 35 20 6d 6f 64 75 6c 65 73 20 6c 6f 61 64 65 64 20 69 6e 20 74 68 65 20 70 72 6f 63 65 73 73 20 75 73 69 6e 67 20 76 75 6c 6e 65 72 61 62 6c 65 20 64 72 69 76 65 72 } //1 snatching 5 modules loaded in the process using vulnerable driver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}