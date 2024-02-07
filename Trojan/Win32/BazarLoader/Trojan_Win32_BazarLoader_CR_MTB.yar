
rule Trojan_Win32_BazarLoader_CR_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {69 6e 69 74 42 75 66 66 65 72 } //03 00  initBuffer
		$a_81_1 = {75 6e 69 6e 69 74 42 75 66 66 65 72 } //03 00  uninitBuffer
		$a_81_2 = {75 70 64 61 74 65 42 75 66 66 65 72 } //03 00  updateBuffer
		$a_81_3 = {45 63 66 63 67 63 69 61 77 66 73 70 56 67 7a 66 73 6c 74 69 6c 71 6a } //03 00  EcfcgciawfspVgzfsltilqj
		$a_81_4 = {4e 6d 6d 77 6e 6c 75 64 78 58 6a 63 6f 61 6f 53 76 68 78 6f 62 6c } //00 00  NmmwnludxXjcoaoSvhxobl
	condition:
		any of ($a_*)
 
}