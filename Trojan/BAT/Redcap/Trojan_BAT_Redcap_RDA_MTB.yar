
rule Trojan_BAT_Redcap_RDA_MTB{
	meta:
		description = "Trojan:BAT/Redcap.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 33 31 37 61 30 64 38 2d 66 65 38 62 2d 34 62 64 36 2d 61 66 31 33 2d 62 32 33 30 31 36 64 39 36 32 31 33 } //1 c317a0d8-fe8b-4bd6-af13-b23016d96213
		$a_01_1 = {53 68 65 6c 6c 52 75 6e 6e 65 72 4e 75 6d 61 } //1 ShellRunnerNuma
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 79 75 6b 61 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 53 68 65 6c 6c 52 75 6e 6e 65 72 5c 53 68 65 6c 6c 52 75 6e 6e 65 72 4e 75 6d 61 5c 6f 62 6a 5c 78 36 34 5c 44 65 62 75 67 5c 53 68 65 6c 6c 52 75 6e 6e 65 72 4e 75 6d 61 2e 70 64 62 } //1 C:\Users\yukan\source\repos\ShellRunner\ShellRunnerNuma\obj\x64\Debug\ShellRunnerNuma.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}