
rule Trojan_Win32_GuLoader_RDW_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 79 6d 62 6f 6c 69 73 65 72 73 20 64 65 74 72 61 63 74 69 6f 6e 20 73 65 6d 61 6e 74 6f 6c 6f 67 69 63 61 6c } //1 symbolisers detraction semantological
		$a_81_1 = {75 64 6b 6f 6d 6d 61 6e 64 65 72 65 64 65 73 20 63 61 6e 74 69 6c 79 } //1 udkommanderedes cantily
		$a_81_2 = {62 72 79 64 65 72 69 65 74 } //1 bryderiet
		$a_81_3 = {64 69 61 73 6b 6f 70 65 72 6e 65 2e 65 78 65 } //1 diaskoperne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}