
rule Trojan_Win32_GuLoader_RAM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {70 68 69 6c 6f 67 65 6e 69 74 69 76 65 6e 65 73 73 20 6b 65 6c 64 73 } //1 philogenitiveness kelds
		$a_81_1 = {61 70 70 65 6e 64 69 63 65 73 } //1 appendices
		$a_81_2 = {66 6c 6f 72 69 73 74 69 63 20 6f 70 76 65 72 2e 65 78 65 } //1 floristic opver.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}