
rule Trojan_Win32_GuLoader_REN_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6c 61 61 6e 65 6b 6f 6e 74 6f 72 65 72 73 } //1 laanekontorers
		$a_81_1 = {65 6a 61 63 75 6c 61 74 65 20 6f 63 63 75 6c 74 61 74 69 6f 6e 20 75 61 66 68 61 65 6e 67 69 67 68 65 64 } //1 ejaculate occultation uafhaengighed
		$a_81_2 = {6d 61 72 6d 6f 72 65 72 65 64 65 73 } //1 marmoreredes
		$a_81_3 = {73 63 6f 6f 6e 20 68 65 72 72 65 6c 69 76 2e 65 78 65 } //1 scoon herreliv.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}