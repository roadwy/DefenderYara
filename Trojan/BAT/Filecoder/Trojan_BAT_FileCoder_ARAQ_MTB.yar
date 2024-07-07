
rule Trojan_BAT_FileCoder_ARAQ_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 72 61 6e 73 6f 6d 5f 74 65 73 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 61 6e 73 6f 6d 5f 74 65 73 74 2e 70 64 62 } //2 \ransom_test\obj\Debug\ransom_test.pdb
		$a_80_1 = {66 69 6c 65 73 20 61 72 6c 65 61 64 79 20 65 6e 63 72 79 70 74 65 64 } //files arleady encrypted  2
		$a_80_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  2
		$a_80_3 = {50 72 6f 63 65 73 73 68 61 63 6b 65 72 } //Processhacker  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}
rule Trojan_BAT_FileCoder_ARAQ_MTB_2{
	meta:
		description = "Trojan:BAT/FileCoder.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 42 79 74 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 42 79 74 65 2e 70 64 62 } //4 \Byte\obj\Debug\Byte.pdb
		$a_80_1 = {46 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 3a 20 7b 30 7d 20 7c 20 50 61 79 6d 65 6e 74 3a 20 7b 31 7d 20 7c 20 53 74 61 74 75 73 3a 20 7b 32 7d } //Files encrypted: {0} | Payment: {1} | Status: {2}  2
		$a_80_2 = {50 61 69 64 20 62 75 74 20 77 61 69 74 69 6e 67 20 66 6f 72 20 31 20 63 6f 6e 66 69 72 6d 61 74 69 6f 6e } //Paid but waiting for 1 confirmation  2
	condition:
		((#a_01_0  & 1)*4+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=8
 
}