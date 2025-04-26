
rule Trojan_BAT_Bsymem_NB_MTB{
	meta:
		description = "Trojan:BAT/Bsymem.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {28 45 00 00 06 17 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 20 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 2c 0a 28 ?? ?? ?? 06 38 ?? ?? ?? 00 7e ?? ?? ?? 04 20 ?? ?? ?? 06 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a } //5
		$a_01_1 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {42 00 61 00 6e 00 64 00 69 00 7a 00 69 00 70 00 } //1 Bandizip
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}