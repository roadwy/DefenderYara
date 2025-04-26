
rule Trojan_Win32_GuLoader_RBD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {76 65 72 64 65 6e 73 6c 69 74 74 65 72 61 74 75 72 65 72 6e 65 } //1 verdenslitteraturerne
		$a_81_1 = {6d 69 72 7a 61 20 65 6e 75 6e 63 69 61 74 69 6f 6e } //1 mirza enunciation
		$a_81_2 = {62 79 72 65 74 73 64 6f 6d 6d 65 72 65 73 2e 65 78 65 } //1 byretsdommeres.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}