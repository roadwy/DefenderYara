
rule Trojan_BAT_Mikey_ND_MTB{
	meta:
		description = "Trojan:BAT/Mikey.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 03 06 ?? ?? 00 00 0a 61 d2 9c 06 17 58 0a 06 02 8e 69 } //5
		$a_81_1 = {2d 2d 20 42 55 49 4c 44 3a } //1 -- BUILD:
		$a_81_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_81_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=9
 
}