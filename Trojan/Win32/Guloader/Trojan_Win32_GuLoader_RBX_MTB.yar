
rule Trojan_Win32_GuLoader_RBX_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {69 6e 64 65 73 6c 75 74 20 66 72 69 74 69 64 73 62 75 6b 73 65 72 20 6b 76 61 64 65 72 73 74 65 6e } //1 indeslut fritidsbukser kvadersten
		$a_81_1 = {66 65 72 69 65 72 65 6a 73 65 6e 64 65 20 73 63 72 75 70 6c 65 } //1 ferierejsende scruple
		$a_81_2 = {68 76 6f 72 64 61 6e } //1 hvordan
		$a_81_3 = {70 72 65 6d 6f 75 72 6e } //1 premourn
		$a_81_4 = {70 72 6f 66 66 65 73 69 6f 6e 65 6c 6c 65 2e 65 78 65 } //1 proffesionelle.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}