
rule Trojan_Win32_GuLoader_RBL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 75 62 66 6f 72 6d 61 74 69 76 65 6e 65 73 73 20 63 68 61 72 74 72 69 6e 67 65 6e 73 20 70 6a 6b 6b 65 72 69 65 74 } //1 subformativeness chartringens pjkkeriet
		$a_81_1 = {73 63 68 72 65 63 6b 6c 69 63 68 } //1 schrecklich
		$a_81_2 = {64 72 65 61 6d 69 6e 67 66 75 6c 20 66 69 67 75 72 65 68 65 61 64 73 20 7a 6f 6f 6c 6f 67 65 72 } //1 dreamingful figureheads zoologer
		$a_81_3 = {74 76 61 6e 67 73 72 75 74 65 6e 73 20 69 6e 76 65 72 73 69 6f 6e 73 2e 65 78 65 } //1 tvangsrutens inversions.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}