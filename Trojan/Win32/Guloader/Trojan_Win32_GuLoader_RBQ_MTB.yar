
rule Trojan_Win32_GuLoader_RBQ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6a 6f 68 6e 61 64 72 65 61 6d 73 20 62 6c 61 64 6d 61 76 65 20 65 6d 62 6f 73 73 65 64 } //1 johnadreams bladmave embossed
		$a_81_1 = {70 72 65 63 6f 6e 74 65 6d 70 6f 72 61 72 79 } //1 precontemporary
		$a_81_2 = {64 65 70 72 65 73 73 69 76 74 } //1 depressivt
		$a_81_3 = {69 6e 74 65 72 6d 6f 72 61 69 6e 69 63 20 72 65 63 74 69 66 69 65 72 } //1 intermorainic rectifier
		$a_81_4 = {73 74 69 6c 74 69 66 79 69 6e 67 20 72 65 67 69 73 74 65 72 74 65 6b 73 74 65 6e 73 2e 65 78 65 } //1 stiltifying registertekstens.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}