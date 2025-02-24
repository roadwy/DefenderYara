
rule HackTool_BAT_CryptInject_NIT_MTB{
	meta:
		description = "HackTool:BAT/CryptInject.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 18 5b 02 08 18 6f 68 01 00 0a 1f 10 28 6d 01 00 0a 9c 08 18 58 0c 08 06 32 e4 } //2
		$a_01_1 = {02 28 08 00 00 06 7e 0e 00 00 04 25 2d 17 26 7e 0a 00 00 04 fe 06 1c 00 00 06 73 41 00 00 0a 25 80 0e 00 00 04 28 07 00 00 2b 28 08 00 00 2b 0a 28 43 00 00 0a 03 6f 44 00 00 0a 06 06 8e 69 28 06 00 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule HackTool_BAT_CryptInject_NIT_MTB_2{
	meta:
		description = "HackTool:BAT/CryptInject.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0d 00 02 28 ?? 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 de 21 } //2
		$a_03_1 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 fe 04 0d 09 2d e0 } //2
		$a_01_2 = {5c 6f 62 6a 5c 44 65 62 75 67 5c 4c 6f 61 64 65 72 2e 70 64 62 } //2 \obj\Debug\Loader.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}