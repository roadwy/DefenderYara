
rule Trojan_Win32_GuLoader_REG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6c 65 74 76 67 74 65 72 65 20 75 6e 64 65 72 63 72 6f 73 73 69 6e 67 } //1 letvgtere undercrossing
		$a_81_1 = {63 6c 65 61 76 6c 61 6e 64 } //1 cleavland
		$a_81_2 = {6e 65 64 6e 6f 72 6d 65 72 69 6e 67 20 6b 61 6c 6d 79 6b 6b 65 6e 73 20 6f 76 65 72 68 61 72 73 68 6c 79 } //1 nednormering kalmykkens overharshly
		$a_81_3 = {70 72 65 72 65 76 69 73 69 6e 67 20 62 69 6c 63 6f 63 6b 20 65 72 68 76 65 72 76 73 66 69 73 6b 65 72 65 73 } //1 prerevising bilcock erhvervsfiskeres
		$a_81_4 = {68 61 70 74 65 6e 65 20 6f 72 64 66 6f 72 72 61 61 64 73 2e 65 78 65 } //1 haptene ordforraads.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}