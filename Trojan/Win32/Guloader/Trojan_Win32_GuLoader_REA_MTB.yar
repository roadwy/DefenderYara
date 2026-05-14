
rule Trojan_Win32_GuLoader_REA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {74 6f 77 6e 65 72 20 73 69 70 68 6f 6e 6f 62 72 61 6e 63 68 69 61 74 65 20 63 6f 6c 69 62 61 6b 74 65 72 69 65 } //1 towner siphonobranchiate colibakterie
		$a_81_1 = {62 65 6c 61 65 67 6e 69 6e 67 20 63 68 61 6c 6f 74 74 65 6c 67 65 6e 65 } //1 belaegning chalottelgene
		$a_81_2 = {69 6e 64 73 65 6e 64 6e 64 65 20 70 72 69 76 61 74 69 7a 65 64 } //1 indsendnde privatized
		$a_81_3 = {66 61 61 72 20 64 69 6e 67 65 6e 6f 74 65 6e 73 20 6b 6f 6f 72 64 69 6e 61 74 6f 72 65 6e } //1 faar dingenotens koordinatoren
		$a_81_4 = {70 69 74 73 69 64 65 2e 65 78 65 } //1 pitside.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}