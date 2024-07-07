
rule Trojan_Win64_DataBinLoader_A{
	meta:
		description = "Trojan:Win64/DataBinLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 61 74 61 20 66 69 6c 65 20 6c 6f 61 64 65 64 2e 20 52 75 6e 6e 69 6e 67 2e 2e 2e 0a } //1
		$a_01_1 = {4e 6f 20 6b 65 79 20 69 6e 20 61 72 67 73 21 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}