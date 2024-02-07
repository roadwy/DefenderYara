
rule Trojan_BAT_FileCoder_ARAQ_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 72 61 6e 73 6f 6d 5f 74 65 73 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 61 6e 73 6f 6d 5f 74 65 73 74 2e 70 64 62 } //02 00  \ransom_test\obj\Debug\ransom_test.pdb
		$a_80_1 = {66 69 6c 65 73 20 61 72 6c 65 61 64 79 20 65 6e 63 72 79 70 74 65 64 } //files arleady encrypted  02 00 
		$a_80_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  02 00 
		$a_80_3 = {50 72 6f 63 65 73 73 68 61 63 6b 65 72 } //Processhacker  00 00 
	condition:
		any of ($a_*)
 
}